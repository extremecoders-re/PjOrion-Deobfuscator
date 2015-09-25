import types
import opcode
import collections
import Queue
import marshal
import pydotplus
import cStringIO


class BasicBlock:
    def __init__(self):
        self.addr = 0
        self.predecessors = []
        self.successors = []
        self.instructions = []
        self.refHandlerIns = []
        self.isHandler = False
        self.isEntry = False
        self.b_seen = False # b_seen is used to perform a DFS of basicblocks


    def addPredecessor(self, bb):
        self.predecessors.append(bb)


    def addSuccessor(self, bb):
        self.successors.append(bb)


    def addInstruction(self, ins):
        self.instructions.append(ins)
        
    def blockSize(self):
        return reduce(lambda size, ins: size + ins.size, self.instructions, 0)


class Instruction:
    def __init__(self, opkode, arg, size):
        self.opkode = opkode
        self.arg = arg
        self.size = size


class Disassembler:
    def __init__(self, code_object):
        assert isinstance(code_object, types.CodeType)
        self.c_stream = map(ord, code_object.co_code)


    def disasAt(self, offset):
        assert offset < len(self.c_stream)

        opkode = self.c_stream[offset]

        # Invalid instruction
        if opkode not in opcode.opmap.values():
            return Instruction(-1, None, 1)

        if opkode < opcode.HAVE_ARGUMENT:
            return Instruction(opkode, None, 1)

        if opkode >= opcode.HAVE_ARGUMENT:
            arg = (self.c_stream[offset + 2] << 8 ) | self.c_stream[offset + 1]
            return Instruction(opkode, arg, 3)


def isRetIns(ins):
    return ins.opkode == opcode.opmap['RETURN_VALUE']


def isBranchIns(ins):
    branchIns = [opcode.opmap[x] for x in [\
        'JUMP_IF_FALSE_OR_POP', \
        'JUMP_IF_TRUE_OR_POP', \
        'JUMP_ABSOLUTE', \
        'POP_JUMP_IF_FALSE',\
        'POP_JUMP_IF_TRUE',\
        'CONTINUE_LOOP',\
        'FOR_ITER',\
        'JUMP_FORWARD',\
        ]]

    return ins.opkode in branchIns


def isCondiBranchIns(ins):
    condiBranchIns = [opcode.opmap[x] for x in [\
        'JUMP_IF_FALSE_OR_POP', \
        'JUMP_IF_TRUE_OR_POP', \
        'POP_JUMP_IF_FALSE',\
        'POP_JUMP_IF_TRUE',\
        'FOR_ITER',\
        ]]

    return ins.opkode in condiBranchIns


def isHandlerIns(ins):
    handlerIns = [opcode.opmap[x] for x in ['SETUP_LOOP', 'SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH']]
    return ins.opkode in handlerIns


def getInsCrossRef(ins, addr):
    targets = []

    if ins.opkode == opcode.opmap['JUMP_IF_FALSE_OR_POP']:
        targets.append(addr + ins.size)
        targets.append(ins.arg)

    elif ins.opkode == opcode.opmap['JUMP_IF_TRUE_OR_POP']:
        targets.append(addr + ins.size)
        targets.append(ins.arg)

    elif ins.opkode == opcode.opmap['JUMP_ABSOLUTE']:
        targets.append(ins.arg)

    elif ins.opkode == opcode.opmap['POP_JUMP_IF_FALSE']:
        targets.append(addr + ins.size)
        targets.append(ins.arg)

    elif ins.opkode == opcode.opmap['POP_JUMP_IF_TRUE']:
        targets.append(addr + ins.size)
        targets.append(ins.arg)

    elif ins.opkode == opcode.opmap['CONTINUE_LOOP']:
        targets.append(ins.arg)

    elif ins.opkode == opcode.opmap['FOR_ITER']:
        targets.append(addr + ins.size)
        targets.append(addr + ins.size + ins.arg)

    elif ins.opkode == opcode.opmap['JUMP_FORWARD']:
        targets.append(addr + ins.size + ins.arg)

    elif ins.opkode == opcode.opmap['SETUP_LOOP']:
        targets.append(addr + ins.size)
        targets.append(addr + ins.size + ins.arg)


    elif ins.opkode == opcode.opmap['SETUP_EXCEPT']:
        targets.append(addr + ins.size)
        targets.append(addr + ins.size + ins.arg)

    elif ins.opkode == opcode.opmap['SETUP_FINALLY']:
        targets.append(addr + ins.size)
        targets.append(addr + ins.size + ins.arg)

    elif ins.opkode == opcode.opmap['SETUP_WITH']:
        targets.append(addr + ins.size)
        targets.append(addr + ins.size + ins.arg)

    elif ins.opkode != opcode.opmap['RETURN_VALUE']:
        targets.append(addr + ins.size)

    return targets


def  _leaderSortFunc(elem1, elem2):
    if elem1.addr != elem2.addr:
        return elem1.addr - elem2.addr
    else:
        if elem1.type == 'S':
            return -1
        else:
            return 1


def findLeaders(code_object, oep):
    Leader = collections.namedtuple('leader', ['type', 'addr'])

    leader_set = set()
    leader_set.add(Leader('S', oep))

    # Queue to contain list of addresses to be analyzed by linear sweep disassembly algorithm
    analysis_Q = Queue.Queue()
    analysis_Q.put(oep)

    analyzed_addresses = set()

    disassembler = Disassembler(code_object)

    while not analysis_Q.empty():
        addr = analysis_Q.get()

        while True:
            ins = disassembler.disasAt(addr)
            analyzed_addresses.add(addr)

            # If current instruction is a return, stop disassembling further
            # current address is an end leader
            if isRetIns(ins):
                leader_set.add(Leader('E', addr))
                break

            # If current instruction is braching, stop disassembling further
            # the current instr is an end leader, branch target is start leader
            if isBranchIns(ins):
                leader_set.add(Leader('E', addr))
                for target in getInsCrossRef(ins, addr):
                    leader_set.add(Leader('S', target))
                    if target not in analyzed_addresses:
                        analysis_Q.put(target)
                break

            # Current instruction is not branching
            else:
                # Get cross refs
                cross_refs = getInsCrossRef(ins, addr)
                addr = cross_refs[0] # The immediate next instruction

                # Some non branching instructions like SETUP_LOOP,
                # SETUP_EXCEPT can have more than 1 cross references
                if len(cross_refs) == 2:
                    leader_set.add(Leader('S', cross_refs[1]))

                    if cross_refs[1] not in analyzed_addresses:
                        analysis_Q.put(cross_refs[1])

    return sorted(leader_set, cmp = _leaderSortFunc)



def buildBasicBlocks(leaders, code_object, entry_addr):
    i = 0
    bb_list = []
    disassembler = Disassembler(code_object)

    while i < len(leaders):
        leader1, leader2 = leaders[i], leaders[i+1]
        addr1, addr2 = leader1.addr, leader2.addr
        bb = BasicBlock()
        bb_list.append(bb)
        bb.addr = addr1
        offset = 0
        if addr1 == entry_addr:
            bb.isEntry = True

        if leader1.type == 'S' and leader2.type == 'E':
            while addr1 + offset <= addr2:
                ins = disassembler.disasAt(addr1  + offset)
                bb.addInstruction(ins)
                offset += ins.size
            i += 2

        elif leader1.type == 'S' and leader2.type == 'S':
            while addr1 + offset < addr2:
                ins = disassembler.disasAt(addr1  + offset)
                bb.addInstruction(ins)
                offset += ins.size
            i += 1

    return bb_list


def insMnemonic(ins):
    return opcode.opname[ins.opkode]


def findbbinBBList(bb_list, bb_addr):
    for i in range(len(bb_list)):
        if bb_list[i].addr == bb_addr:
            return i

    raise Exception("No basic block with an address {} exists!!".format(bb_addr))  # Should not happen


def buildPositionIndepedentBasicBlock(bb_list):
    for bb in bb_list:
        offset = 0
        for i in range(len(bb.instructions)):
            ins = bb.instructions[i]

            # The last ins of a bb is processed specially
            if i == len(bb.instructions) - 1:
                cross_ref = getInsCrossRef(ins, bb.addr + offset)

                if isBranchIns(ins):

                    # Conditional branch ins have 2 cross refs
                    if isCondiBranchIns(ins):
                        # ref1 is the address of next instruction
                        # ref2 is the address of the branch target
                        ref1, ref2 = cross_ref[0], cross_ref[1]

                        pos = findbbinBBList(bb_list, ref2)
                        ins.arg = bb_list[pos]
                        bb.addSuccessor(bb_list[pos])
                        bb_list[pos].addPredecessor(bb)

                        pos = findbbinBBList(bb_list, ref1)
                        bb.addSuccessor(bb_list[pos])
                        bb_list[pos].addPredecessor(bb)


                    # Unconditional branch ins have 1 cross ref
                    else:
                        ref = cross_ref[0]
                        pos = findbbinBBList(bb_list, ref)
                        ins.arg = bb_list[pos]
                        bb.addSuccessor(bb_list[pos])
                        bb_list[pos].addPredecessor(bb)


                # FOR_ITER, SETUP_LOOP, SETUP_EXCEPT, SETUP_FINALLY, SETUP_WITH
                # They have 2 cross refs
                elif isHandlerIns(ins):
                    # ref1 is the address of next instruction
                    # ref2 is the address of the handler
                    ref1, ref2 = cross_ref[0], cross_ref[1]

                    pos = findbbinBBList(bb_list, ref2)
                    bb_list[pos].isHandler = True
                    bb_list[pos].refHandlerIns.append(ins)

                    ins.arg = bb_list[pos]
                    pos = findbbinBBList(bb_list, ref1)
                    bb.addSuccessor(bb_list[pos])
                    bb_list[pos].addPredecessor(bb)


                # For RETURN_VALUE instruction, nothing to do
                elif isRetIns(ins):
                    pass


                # Normal instructions, have only 1 cross ref
                else:
                    ref = cross_ref[0]
                    pos = findbbinBBList(bb_list, ref)
                    bb.addSuccessor(bb_list[pos])
                    bb_list[pos].addPredecessor(bb)


            # Not the last instruction
            else:
                if isHandlerIns(ins):
                    ref = getInsCrossRef(ins, bb.addr + offset)[1]
                    pos = findbbinBBList(bb_list, ref)
                    bb_list[pos].isHandler = True
                    bb_list[pos].refHandlerIns.append(ins)

                    ins.arg = bb_list[pos]

            offset += ins.size


def findOEP(code_object):
    '''
    Finds the original entry point of a code object obfuscated by PjOrion.
    DO NOT call this for a non obfsucated code object.
    
    :param code_object: the code object
    :type code_object: code    
    :returns: the entrypoint
    :rtype: int
    '''    
    disassembler = Disassembler(code_object)
    ins = disassembler.disasAt(0)

    try:
        assert insMnemonic(ins) == 'SETUP_EXCEPT'
        except_handler = 0 + ins.arg + ins.size

        assert disassembler.disasAt(3).opkode == -1
        assert insMnemonic(disassembler.disasAt(except_handler)) == 'POP_TOP'
        assert insMnemonic(disassembler.disasAt(except_handler + 1)) == 'POP_TOP'
        assert insMnemonic(disassembler.disasAt(except_handler + 2)) == 'POP_TOP'
        return except_handler + 3
    except:
        return -1


def simplifyPass1(bb_list):
    """
    Eliminates a basic block that only contains an unconditional branch.
    """
    foo = True

    while foo:
        foo = False
        for i in range(len(bb_list)):
            bb = bb_list[i]
            if bb.isHandler and len(bb.instructions) == 1:
                ins = bb.instructions[0]
                if insMnemonic(ins) == 'JUMP_FORWARD' or insMnemonic(ins) == 'JUMP_ABSOLUTE':
                    branch_target_bb = bb.successors[0] # Branch target of this basic block
                    branch_target_bb.predecessors.remove(bb)

                    branch_target_bb.isHandler = True
                    for refIns in bb.refHandlerIns:
                        refIns.arg = branch_target_bb

                    branch_target_bb.refHandlerIns = bb.refHandlerIns

                    # Now iterate over all predecessors of this bb
                    for j in range(len(bb.predecessors)):
                        # Remove this bb from the successor list
                        # Add branch target bb to the successor list
                        bb.predecessors[j].successors.remove(bb)
                        bb.predecessors[j].addSuccessor(branch_target_bb)
                        branch_target_bb.addPredecessor(bb.predecessors[j])

                        last_ins = bb.predecessors[j].instructions[-1]
                        if last_ins.opkode in opcode.hasjabs or last_ins.opkode in opcode.hasjrel:
                            last_ins.arg = branch_target_bb

                    del bb_list[i]
                    foo = True
                    break


            elif not bb.isHandler and len(bb.instructions) == 1:
                ins = bb.instructions[0]
                if insMnemonic(ins) == 'JUMP_FORWARD' or insMnemonic(ins) == 'JUMP_ABSOLUTE':
                    branch_target_bb = bb.successors[0] # Branch target of this basic block
                    branch_target_bb.predecessors.remove(bb)

                    # Now iterate over all predecessors of this bb
                    for j in range(len(bb.predecessors)):
                        # Remove this bb from the successor list
                        # Add branch target bb to the successor list
                        bb.predecessors[j].successors.remove(bb)
                        bb.predecessors[j].addSuccessor(branch_target_bb)
                        branch_target_bb.addPredecessor(bb.predecessors[j])

                        last_ins = bb.predecessors[j].instructions[-1]
                        if last_ins.opkode in opcode.hasjabs or last_ins.opkode in opcode.hasjrel:
                            last_ins.arg = branch_target_bb

                    del bb_list[i]
                    foo = True
                    break



def simplifyPass2(bb_list):
    """
    Merges a basic block into its predecessor if there is only one and the
    predecessor only has one successor.
    """

    foo = True
    while foo:
        foo = False
        for i in range(len(bb_list)):
            bb = bb_list[i]

            # Not a handler block & has only 1 predecessor
            if not bb.isHandler and len(bb.predecessors) == 1:
                pred = bb.predecessors[0]
                # Predecessor has only 1 successor
                if len(pred.successors) == 1:
                    # Merge this bb with its predecessor
                    last_ins_pred = pred.instructions[-1]

                    # If last instruction of predecessor is either JUMP_ABSOLUTE or JUMP_FORWARD, delete it
                    if insMnemonic(last_ins_pred) == 'JUMP_ABSOLUTE' or insMnemonic(last_ins_pred) == 'JUMP_FORWARD':
                        del pred.instructions[-1]

                    # Append all instructions of current bb
                    for ins in bb.instructions:
                        pred.addInstruction(ins)

                    del pred.successors[:]

                    for succ in bb.successors:
                        pred.addSuccessor(succ)
                        succ.predecessors.remove(bb)
                        succ.addPredecessor(pred)

                    del bb_list[i]
                    foo = True
                    break


def bbToDot(bb):
    dot = '<<table align = "left" border = "0">'
    if bb.isEntry:
        dot += '<tr><td align = "left"><font point-size = "8" color = "#9dd600">entrypoint:</font></td></tr>'

    elif bb.isHandler:
        dot += '<tr><td align = "left"><font point-size = "8" color = "#9dd600">handler:</font></td></tr>'

    #else:
    #    dot += '<tr><td align = "left"><font point-size = "8" color = "#9dd600">off_{}:</font></td></tr>'.format(bb.addr)

    for ins in bb.instructions:
        dot += '<tr><td align = "left">{}</td></tr>'.format(insMnemonic(ins))
    dot += '</table>>'

    return pydotplus.Node('off_{}'.format(bb.addr), shape='none', style='filled', color='#2d2d2d',
                        label=dot, fontcolor='white', fontname='Consolas', fontsize='9')


def buildEdges(graph, nodelist, bb_list):
    for i in range(len(bb_list)):
        bb = bb_list[i]
        for succ in bb.successors:
            graph.add_edge(pydotplus.Edge(nodelist[i], nodelist[bb_list.index(succ)]))


def buildGraph(bb_list):
    graph = pydotplus.Dot(graph_type='digraph')
    # graph.set('splines', 'curved')
    nodelist = []
    for bb in bb_list:
        node = bbToDot(bb)
        graph.add_node(node)
        nodelist.append(node)

    buildEdges(graph, nodelist, bb_list)
    graph.write_svg('1_d.svg')



class Assembler:
    def __init__(self, bb_list):
        self.bb_list = bb_list
        self.a_postorder = [None] * len(bb_list)
        self.a_nblocks = 0
        
    
    def assemble(self):
        for bb in self.bb_list:
            if bb.isEntry:
                self._dfs(bb)
                break
            
        # Can't modify the bytecode after computing jump offsets.
        self._assembleJumpOffsets()            
        return self._emit()
                
    
    def _assembleIns(self, ins):
        size = ins.size
        
        if ins.opkode >= opcode.HAVE_ARGUMENT:
            arg = ins.arg
            
        if size == 1:
            return chr(ins.opkode)
        
        elif size == 3:
            return chr(ins.opkode) + chr(arg & 0xFF) + chr((arg >> 8) & 0xFF)
        
        else:
            raise Exception('EXTENDED_ARG not yet implemented')
    
    
    def _emit(self):
        code = cStringIO.StringIO()
        for i in range(len(self.a_postorder) - 1, -1, -1):
            bb = self.a_postorder[i]
            
            for ins in bb.instructions:
                code.write(self._assembleIns(ins))
                
        return code.getvalue()             
        
        
    def _dfs(self, bb):
        if bb.b_seen:
            return
        bb.b_seen = True
        
        if len(bb.successors) > 0:
            self._dfs(bb.successors[0])
            
        
        for i in range(len(bb.instructions)):
            ins = bb.instructions[i]
            if isinstance(ins.arg, BasicBlock):
            #if ins.opkode in opcode.hasjabs or ins.opkode in opcode.hasjrel:
                self._dfs(ins.arg)
                
        
        if len(bb.successors) == 2:
            self._dfs(bb.successors[1])
        
        self.a_postorder[self.a_nblocks] = bb
        self.a_nblocks += 1
        
        
    def _assembleJumpOffsets(self):
        totsize = 0
        
        # Iterate in reverse order and calculate the addresses of each bb
        for i in range(len(self.a_postorder) - 1, -1, -1):
            bsize = self.a_postorder[i].blockSize()
            self.a_postorder[i].addr = totsize
            totsize += bsize
            
        # We have calculated the offsets of each bb
        
        for bb in self.a_postorder:
            bsize = bb.addr
            for ins in bb.instructions:
                bsize += ins.size
                if ins.opkode in opcode.hasjabs:
                    ins.arg = ins.arg.addr
                    
                elif ins.opkode in opcode.hasjrel:
                    ins.arg = ins.arg.addr - bsize
        
        

def deobfuscate(code_object):
    assert isinstance(code_object, types.CodeType)
    oep = findOEP(code_object)

    if oep == -1:
        print 'Not generating cfg for ', code_object.co_name
        return code_object.co_code

    leader_set = findLeaders(code_object, oep)
    bb_list = buildBasicBlocks(leader_set, code_object, oep)
    buildPositionIndepedentBasicBlock(bb_list)
    print 'Original number of basic blocks: ', len(bb_list)
    simplifyPass1(bb_list)
    print 'Number of basic blocks after pass 1: ', len(bb_list)
    simplifyPass2(bb_list)
    print 'Number of basic blocks after pass 2: ', len(bb_list)
    #buildGraph(bb_list)
    return Assembler(bb_list).assemble()
    

def recurseCodeObjects(code_obj):
    mod_const = []
    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType):
            mod_const.append(recurseCodeObjects(const))
        else:
            mod_const.append(const)

    argcount = code_obj.co_argcount
    nlocals = code_obj.co_nlocals
    stacksize = code_obj.co_stacksize
    flags = code_obj.co_flags
    codestring = deobfuscate(code_obj)
    constants = tuple(mod_const)
    names = code_obj.co_names
    varnames = tuple('var{}'.format(i) for i in range(len(code_obj.co_varnames)))
    filename = code_obj.co_filename
    import random
    name = str(random.randint(100,999)) # 'renamed'  # XXX: Use a better way
    firstlineno = code_obj.co_firstlineno
    lnotab = code_obj.co_lnotab
    

    return types.CodeType(argcount, nlocals, stacksize, \
                          flags, codestring, constants, names, \
                          varnames,
                          filename, 
                          name, 
                          firstlineno, 
                          lnotab)

def main():
    fSrc = open('ob1.pyc', 'rb')
    fSrc.seek(8)
    c_obj = marshal.load(fSrc)
    fSrc.close()
    fOut = open('ob1_deobf.pyc', 'wb') 
    fOut.write('\x03\xf3\x0d\x0a\0\0\0\0')
    marshal.dump(recurseCodeObjects(c_obj), fOut)
    fOut.close()


if __name__ == '__main__':
    main()