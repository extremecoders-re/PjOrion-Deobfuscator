import opcode
import pydotplus

from basicblock import BasicBlock
from instruction import Instruction
import utils


def createAbsJmpBb(target_bb):
    bb = BasicBlock()
    ins = Instruction(opcode.opmap['JUMP_ABSOLUTE'], target_bb, 3)
    bb.instructions.append(ins)
    return bb
 

def insMnemonic(ins):
    return opcode.opname[ins.opkode]   
    
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
    
def isRelJmpIns(ins):
    return ins.opkode in opcode.hasjrel
    
    
def findbbinBBList(bb_list, bb_addr):
    for i in range(len(bb_list)):
        if bb_list[i].addr == bb_addr:
            return i

    raise Exception("No basic block with an address {} exists!!".format(bb_addr))  # Should not happen    
    
def bbToDot(bb):
    dot = '<<table align = "left" border = "0">'
    if bb.isEntry:
        dot += '<tr><td align = "left"><font point-size = "8" color = "#9dd600">entrypoint:</font></td></tr>'

    elif bb.isHandler:
        dot += '<tr><td align = "left"><font point-size = "8" color = "#9dd600">handler:</font></td></tr>'

    #else:
    #    dot += '<tr><td align = "left"><font point-size = "8" color = "#9dd600">off_{}:</font></td></tr>'.format(bb.addr)

    for ins in bb.instructions:
        dot += '<tr><td align = "left">{}</td></tr>'.format(utils.insMnemonic(ins))
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