import opcode
import types


from instruction import Instruction

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