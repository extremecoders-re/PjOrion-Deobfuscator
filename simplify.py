import opcode

from utils import insMnemonic

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
                