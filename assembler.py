import opcode
import cStringIO

import utils
from basicblock import BasicBlock

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
        
        self.a_postorder.reverse()
        for i in range(len(self.a_postorder)):
            bb = self.a_postorder[i]
            
            for ins in bb.instructions:
                if utils.isRelJmpIns(ins):
                    target_bb = ins.arg
                    if self.a_postorder.index(target_bb) < i:
                        newbb = utils.createAbsJmpBb(target_bb)
                        self.a_postorder.append(newbb)
                        ins.arg = newbb

        utils.buildGraph(self.a_postorder)        
        self.a_postorder.reverse()
                
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
                    assert ins.arg <= 0xFFFF
                    
                elif ins.opkode in opcode.hasjrel:
                    ins.arg = ins.arg.addr - bsize
                    assert ins.arg >= 0
                    assert ins.arg <= 0xFFFF