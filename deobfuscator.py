import types
import opcode
import collections
import Queue
import marshal

import simplify
import utils
from basicblock import BasicBlock
from instruction import Instruction
from disassembler import Disassembler
from assembler import Assembler


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
            if utils.isRetIns(ins):
                leader_set.add(Leader('E', addr))
                break

            # If current instruction is braching, stop disassembling further
            # the current instr is an end leader, branch target is start leader
            if utils.isBranchIns(ins):
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



def buildPositionIndepedentBasicBlock(bb_list):
    for bb in bb_list:
        offset = 0
        for i in range(len(bb.instructions)):
            ins = bb.instructions[i]

            # The last ins of a bb is processed specially
            if i == len(bb.instructions) - 1:
                cross_ref = getInsCrossRef(ins, bb.addr + offset)

                if utils.isBranchIns(ins):

                    # Conditional branch ins have 2 cross refs
                    if utils.isCondiBranchIns(ins):
                        # ref1 is the address of next instruction
                        # ref2 is the address of the branch target
                        ref1, ref2 = cross_ref[0], cross_ref[1]

                        pos = utils.findbbinBBList(bb_list, ref2)
                        ins.arg = bb_list[pos]
                        bb.addSuccessor(bb_list[pos])
                        bb_list[pos].addPredecessor(bb)

                        pos = utils.findbbinBBList(bb_list, ref1)
                        bb.addSuccessor(bb_list[pos])
                        bb_list[pos].addPredecessor(bb)


                    # Unconditional branch ins have 1 cross ref
                    else:
                        ref = cross_ref[0]
                        pos = utils.findbbinBBList(bb_list, ref)
                        ins.arg = bb_list[pos]
                        bb.addSuccessor(bb_list[pos])
                        bb_list[pos].addPredecessor(bb)


                # FOR_ITER, SETUP_LOOP, SETUP_EXCEPT, SETUP_FINALLY, SETUP_WITH
                # They have 2 cross refs
                elif utils.isHandlerIns(ins):
                    # ref1 is the address of next instruction
                    # ref2 is the address of the handler
                    ref1, ref2 = cross_ref[0], cross_ref[1]

                    pos = utils.findbbinBBList(bb_list, ref2)
                    bb_list[pos].isHandler = True
                    bb_list[pos].refHandlerIns.append(ins)

                    ins.arg = bb_list[pos]
                    pos = utils.findbbinBBList(bb_list, ref1)
                    bb.addSuccessor(bb_list[pos])
                    bb_list[pos].addPredecessor(bb)


                # For RETURN_VALUE instruction, nothing to do
                elif utils.isRetIns(ins):
                    pass


                # Normal instructions, have only 1 cross ref
                else:
                    ref = cross_ref[0]
                    pos = utils.findbbinBBList(bb_list, ref)
                    bb.addSuccessor(bb_list[pos])
                    bb_list[pos].addPredecessor(bb)


            # Not the last instruction
            else:
                if utils.isHandlerIns(ins):
                    ref = getInsCrossRef(ins, bb.addr + offset)[1]
                    pos = utils.findbbinBBList(bb_list, ref)
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
        assert utils.insMnemonic(ins) == 'SETUP_EXCEPT'
        except_handler = 0 + ins.arg + ins.size

        assert disassembler.disasAt(3).opkode == -1
        assert utils.insMnemonic(disassembler.disasAt(except_handler)) == 'POP_TOP'
        assert utils.insMnemonic(disassembler.disasAt(except_handler + 1)) == 'POP_TOP'
        assert utils.insMnemonic(disassembler.disasAt(except_handler + 2)) == 'POP_TOP'
        return except_handler + 3
    except:
        return -1


def deobfuscate(code_object):
    assert isinstance(code_object, types.CodeType)
    oep = findOEP(code_object)

    if oep == -1:
        print 'Not generating cfg for ', code_object.co_name
        return code_object.co_code

    leader_set = findLeaders(code_object, oep)
    bb_list = buildBasicBlocks(leader_set, code_object, oep)
    buildPositionIndepedentBasicBlock(bb_list)
    print '--------------------------------------------'
    print 'Original number of basic blocks: ', len(bb_list)
    #simplify. simplifyPass1(bb_list)
    print 'Number of basic blocks after pass 1: ', len(bb_list)
    #simplify.simplifyPass2(bb_list)
    print 'Number of basic blocks after pass 2: ', len(bb_list)
    print '--------------------------------------------'
    #buildGraph(bb_list)
    return Assembler(bb_list).assemble()
    

def recurseCodeObjects(code_obj):
    co_argcount = code_obj.co_argcount
    co_nlocals = code_obj.co_nlocals
    co_stacksize = code_obj.co_stacksize
    co_flags = code_obj.co_flags
    co_codestring = deobfuscate(code_obj)
    
    co_names = code_obj.co_names
    co_varnames = code_obj.co_varnames
    co_filename = code_obj.co_filename
    co_name = code_obj.co_name
    co_firstlineno = code_obj.co_firstlineno
    co_lnotab = code_obj.co_lnotab
    
    
    mod_const = []
    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType):
            mod_const.append(recurseCodeObjects(const))
        else:
            mod_const.append(const)
    
    co_constants = tuple(mod_const)
    
    return types.CodeType(co_argcount, co_nlocals, co_stacksize, co_flags, \
                            co_codestring, co_constants, co_names, co_varnames, \
                            co_filename, co_name, co_firstlineno, co_lnotab)


def main():
    fSrc = open('simple.pyc', 'rb')
    fSrc.seek(8)
    c_obj = marshal.load(fSrc)
    fSrc.close()
    fOut = open('simple_deob.pyc', 'wb') 
    fOut.write('\x03\xf3\x0d\x0a\0\0\0\0')
    marshal.dump(recurseCodeObjects(c_obj), fOut)
    fOut.close()


if __name__ == '__main__':
    main()