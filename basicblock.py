

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