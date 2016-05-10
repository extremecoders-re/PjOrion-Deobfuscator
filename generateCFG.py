'''
Script to render a CFG of all code objects in a pyc file.
It uses a recusrive traversal disassembling strategy, hence it can
deal with obfuscated code objects too.

Note: if variable name obfuscation has been used, rename them before generating CFG
      as, graphviz would not render obfuscated unicode strings.
'''

import marshal
import types
import opcode
import Queue
import collections
import pydotplus
import sys
import os.path

class Instruction:
    def __init__(self, offset, opkode, mnemonic, size, args):
        self.offset = offset
        self.opkode = opkode
        self.mnemonic = mnemonic
        self.size = size
        self.args = args


    def hasArgs(self):
        return self.args != None


    def isAbsoluteJmp(self):
        return self.mnemonic == 'JUMP_ABSOLUTE'


    def isControlFlow(self):
        if self.mnemonic in ['SETUP_LOOP', 'SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH']:
            return False

        if self.opkode in opcode.hasjabs or \
            self.opkode in opcode.hasjrel or \
            self.opkode == opcode.opmap['RETURN_VALUE']:
            return True

        return False


    def isRelativeJmp(self):
        return self.opkode in opcode.hasjrel


    def isReturn(self):
        return self.opkode == opcode.opmap['RETURN_VALUE']


    def canModifyIP(self):
        if self.opkode in [opcode.opmap[x] for x in ['SETUP_LOOP', 'SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH']]:
            return False

        elif self.opkode in opcode.hasjabs or self.opkode in opcode.hasjrel:
            return True

        else:
            return False


    def getCrossReferences(self):
        targets = []

        if self.opkode in opcode.hasjabs:
            if self.opkode == opcode.opmap['JUMP_IF_FALSE_OR_POP']:
                targets.append(self.args)
                targets.append(self.offset + self.size)

            elif self.opkode == opcode.opmap['JUMP_IF_TRUE_OR_POP']:
                targets.append(self.args)
                targets.append(self.offset + self.size)

            elif self.opkode == opcode.opmap['JUMP_ABSOLUTE']:
                targets.append(self.args)

            elif self.opkode == opcode.opmap['POP_JUMP_IF_FALSE']:
                targets.append(self.args)
                targets.append(self.offset + self.size)

            elif self.opkode == opcode.opmap['POP_JUMP_IF_TRUE']:
                targets.append(self.args)
                targets.append(self.offset + self.size)

            elif self.opkode == opcode.opmap['CONTINUE_LOOP']:
                targets.append(self.args)

        elif self.opkode in opcode.hasjrel:
            if self.opkode == opcode.opmap['FOR_ITER']:
                targets.append(self.offset + self.size)
                targets.append(self.offset + self.size + self.args)

            elif self.opkode == opcode.opmap['JUMP_FORWARD']:
                targets.append(self.offset + self.size + self.args)

            elif self.opkode == opcode.opmap['SETUP_LOOP']:
                targets.append(self.offset + self.size)
                targets.append(self.offset + self.size + self.args)

            elif self.opkode == opcode.opmap['SETUP_EXCEPT']:
                targets.append(self.offset + self.size)
                targets.append(self.offset + self.size + self.args)

            elif self.opkode == opcode.opmap['SETUP_FINALLY']:
                targets.append(self.offset + self.size)
                targets.append(self.offset + self.size + self.args)

            elif self.opkode == opcode.opmap['SETUP_WITH']:
                targets.append(self.offset + self.size)
                targets.append(self.offset + self.size + self.args)

        elif self.opkode != opcode.opmap['RETURN_VALUE']:
            targets.append(self.offset + self.size)

        return targets


class Disassembler:
    def __init__(self, c_obj):
        assert isinstance(c_obj, types.CodeType)
        self.c_stream = map(ord, c_obj.co_code)


    def disas(self, offset):
        assert offset < len(self.c_stream)

        opkode = self.c_stream[offset]

        # Invalid instruction
        if opkode not in opcode.opmap.values():
            return Instruction(offset, -1, '<INVALID>', 1, None)

        if opkode < opcode.HAVE_ARGUMENT:
            return Instruction(offset, opkode, opcode.opname[opkode], 1, None)

        if opkode >= opcode.HAVE_ARGUMENT:
            args = (self.c_stream[offset + 2] << 8 ) | self.c_stream[offset + 1]
            return Instruction(offset, opkode, opcode.opname[opkode], 3, args)

# The entry point of the code object
# XXX: Find a better method, than using global variables
entrypoint = 0 


class BasicBlock:
    def __init__(self, start_offset, end_offset, c_obj):
        self.start_offset = start_offset
        self.end_offset = end_offset
        self.c_obj = c_obj
        self.disassembler = Disassembler(self.c_obj)


    def prettyPrint(self):
        print 'off_{}:'.format(self.start_offset)
        offset = self.start_offset

        while offset <= self.end_offset:
            instr = self.disassembler.disas(offset)
            if not instr.hasArgs():
                print offset, instr.mnemonic

            else:
                args = instr.args
                if instr.isRelativeJmp():
                    print offset, instr.mnemonic, args, '(to off_{})'.format(offset + instr.size + args)
                else:
                    print offset, instr.mnemonic, args

            offset += instr.size


    def toDotNode(self):
        global entrypoint
        dot = '<<table align = "left" border = "0">'
        if self.start_offset != entrypoint:
            dot += '<tr><td align = "left"><font point-size = "8" color = "#9dd600">off_{}:</font></td></tr>'.format(self.start_offset)
        else:
            dot += '<tr><td align = "left"><font point-size = "8" color = "#9dd600">entrypoint:</font></td></tr>'

        offset = self.start_offset

        while offset <= self.end_offset:
            instr = self.disassembler.disas(offset)

            dot += '<tr>'
            #dot += '<td align = "left">{}</td>'.format(offset)
            dot += '<td align = "left">{}</td>'.format(instr.mnemonic)

            if instr.hasArgs():
                dot += '<td>     </td>'
                args = instr.args

                if instr.isRelativeJmp():
                    dot += '<td align = "left"><font color = "#73adad">{} (off_{})</font></td>'.format(args, offset + instr.size + args)
                elif instr.isAbsoluteJmp():
                    dot += '<td align = "left"><font color = "#73adad">off_{}</font></td>'.format(args)
                else:
                    #dot += '<td align = "left"><font color = "#73adad">{}</font></td>'.format(args)

                    html_escape_table = {'&' : '&amp;', '"' : '&quot;', "'" : '&apos;', '>' : '&gt;', '<' : '&lt;', '%' : ''}

                    if instr.opkode in opcode.hasname:
                        st = '{}'.format(self.c_obj.co_names[instr.args])
                        st = ''.join(html_escape_table.get(c, c) for c in st)
                        dot += '<td align = "left"><font color = "#73adad">{}</font></td>'.format(st)

                    elif instr.opkode in opcode.hasconst:
                        st = '\'{}\''.format(self.c_obj.co_consts[instr.args])
                        st = ''.join(html_escape_table.get(c, c) for c in st)
                        dot += '<td align = "left"><font color = "#73adad">{}</font></td>'.format(st)

                    elif instr.opkode in opcode.haslocal:
                        st = '{}'.format(self.c_obj.co_varnames[instr.args])
                        st = ''.join(html_escape_table.get(c, c) for c in st)
                        dot += '<td align = "left"><font color = "#73adad">{}</font></td>'.format(st)

                    else:
                        dot += '<td align = "left"><font color = "#73adad">{}</font></td>'.format(args)

            dot += '</tr>'
            offset += instr.size
        dot += '</table>>'
        
        return pydotplus.Node('off_{}'.format(self.start_offset), shape='none', style='filled', color='#2d2d2d',
                        label=dot, fontcolor='white', fontname='Consolas', fontsize='9')


    def getEdgeTargets(self):
        lastInstr = self.disassembler.disas(self.end_offset)
        if lastInstr.mnemonic in ['FOR_ITER','SETUP_LOOP', 'SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH']:
            return [lastInstr.getCrossReferences()[0]]
        return lastInstr.getCrossReferences()


def getLeaders(c_obj, start_offset):
    disassembler = Disassembler(c_obj)
    Leader = collections.namedtuple('leader', ['type', 'address'])

    leader_set = set()
    leader_set.add(Leader('S', start_offset))

    analysis_Q = Queue.Queue()
    analysis_Q.put(start_offset)

    analyzed_addresses = set()

    while not analysis_Q.empty():
        offset = analysis_Q.get()

        while True:
            instr = disassembler.disas(offset)
            analyzed_addresses.add(offset)

            # If current instruction is a return, stop disassembling further
            # current address is an end leader
            if instr.isReturn():
                leader_set.add(Leader('E', offset))
                break

            # If current instruction cannot modify ip, go to sucessor instruction
            elif not instr.canModifyIP():
                offset = instr.getCrossReferences()[0]

                # Current instruction cannot modify ip, but references two location
                # like in SETUP_LOOP, SETUP_EXCEPT etc
                if len(instr.getCrossReferences()) == 2:
                    cross_ref = instr.getCrossReferences()[1]
                    leader_set.add(Leader('S', cross_ref))

                    if cross_ref not in analyzed_addresses:
                        analysis_Q.put(cross_ref)


            # If current instruction can modify IP, stop disassembling further
            # we have more than one branches
            # current instr is an end leader, branch targets are start leaders
            else:
                leader_set.add(Leader('E', offset))
                for target in instr.getCrossReferences():
                    leader_set.add(Leader('S', target))
                    if target not in analyzed_addresses:
                        analysis_Q.put(target)
                break


    def _sortFunction(elem1, elem2):
        if elem1.address != elem2.address:
            return elem1.address - elem2.address
        else:
            if elem1.type == 'S':
                return -1
            else:
                return 1

    return sorted(leader_set, cmp = _sortFunction)


def buildBasicBlocks(leaders, c_obj):
    i = 0
    bb_list = []

    while i < len(leaders):
        leader1 = leaders[i]
        leader2 = leaders[i+1]

        if leader1.type == 'S' and leader2.type == 'E':
            bb = BasicBlock(leader1.address, leader2.address, c_obj)
            bb_list.append(bb)
            i += 2

        elif leader1.type == 'S' and leader2.type == 'S':
            disassembler = Disassembler(c_obj)
            last_offset = -1
            offset = leader1.address

            while offset < leader2.address:
                last_offset = offset
                offset += disassembler.disas(offset).size

            bb = BasicBlock(leader1.address, last_offset, c_obj)
            bb_list.append(bb)
            i += 1

        else:
            raise Exception('This should not happen')

    return bb_list


def buildEdges(graph, bblist, nodelist):
    for i in range(len(bblist)):
        bb = bblist[i]
        targets = bb.getEdgeTargets()

        for t in targets:
            for j in range(len(bblist)):
                if bblist[j].start_offset == t:
                    graph.add_edge(pydotplus.Edge(nodelist[i], nodelist[j]))


def findOEP(code_obj):
    '''
    Finds the original entry point of a code object obfuscated by PjOrion.
    DO NOT call this for a non obfsucated code object.
    
    :param code_obj: the code object
    :type code_obj: code    
    :returns: the entrypoint
    :rtype: int
    '''
    disassembler = Disassembler(code_obj)

    instr = disassembler.disas(0)
    try:
        assert instr.mnemonic == 'SETUP_EXCEPT'

        except_handler = 0 + instr.args + instr.size

        assert disassembler.disas(except_handler).mnemonic == 'POP_TOP'
        assert disassembler.disas(except_handler + 1).mnemonic == 'POP_TOP'
        assert disassembler.disas(except_handler + 2).mnemonic == 'POP_TOP'

        return except_handler + 3
    except:
        return -1
        
        
def drawCFG(code_obj, filename):
    '''
    Draw the CFG of the code object.
    
    :param code_obj: the code object
    :type code_obj: code
    
    :param filename: filename of svg
    :type filename: str
    '''
    global entrypoint

    # For normal codeobjects entrypoint = oep = 0
    #entrypoint = oep = findOEP(code_obj)
    entrypoint = oep = 0
    if oep == -1:
        print 'Not generating cfg for ', code_obj.co_name
        return

    leader_set = getLeaders(code_obj, oep)
    bblist = buildBasicBlocks(leader_set, code_obj)
    nodelist = []
    graph = pydotplus.Dot(graph_type = 'digraph')
    # graph.set('splines', 'curved')

    for bb in bblist:
        node = bb.toDotNode()
        nodelist.append(node)
        graph.add_node(node)

    buildEdges(graph, bblist, nodelist)
    graph.write_svg(filename)
        
        
# XXX: Find a better filenaming convention, may use co_name
i = 1 # Variableto track filename of output svg
filenameprefix = ''

def recurseCodeObjects(c_obj):
    global i, filenameprefix
    drawCFG(c_obj, '{}{}.svg'.format(filenameprefix, i))
    i += 1

    for const in c_obj.co_consts:
        if isinstance(const, types.CodeType):
            recurseCodeObjects(const)


def main():
    global filenameprefix
    if len(sys.argv) < 2:
        print 'Usage: generateCFG.py <pyc file>'
        return
        
    with open(sys.argv[1], 'rb') as fSrc:
        filenameprefix = os.path.splitext(sys.argv[1])[0]
        fSrc.seek(8)
        code_obj = marshal.load(fSrc)
        recurseCodeObjects(code_obj)
        print 'Done...'


if __name__ == '__main__':
    main()