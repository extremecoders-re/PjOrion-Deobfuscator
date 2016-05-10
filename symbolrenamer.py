'''
Script to rename all variable names in a pyc file.
This is done by recursively traversing the code objects.
'''

import marshal
import types
import sys
import random

def rename(code_obj):
    mod_const = []
    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType):
            mod_const.append(rename(const))
        else:
            mod_const.append(const)

    co_argcount = code_obj.co_argcount
    co_nlocals = code_obj.co_nlocals
    co_stacksize = code_obj.co_stacksize
    co_flags = code_obj.co_flags
    co_codestring = code_obj.co_code
    co_constants = tuple(mod_const)
    co_names = code_obj.co_names
    co_varnames = tuple('var{}'.format(i) for i in range(len(code_obj.co_varnames)))
    co_filename = code_obj.co_filename
    co_name = 'co' + str(random.randint(100,999))
    co_firstlineno = code_obj.co_firstlineno
    co_lnotab = code_obj.co_lnotab

    return types.CodeType(co_argcount, co_nlocals, co_stacksize, \
                          co_flags, co_codestring, co_constants, co_names, \
                          co_varnames, co_filename, co_name, co_firstlineno, co_lnotab)


def main():
    if len(sys.argv) < 3:
        print 'Usage: symbolrenamer.py <source pyc> <output pyc>'
        return
    
    else:
        with open(sys.argv[1], 'rb') as fSrc:
            fSrc.seek(8)
            code_obj = marshal.load(fSrc)

        deob = rename(code_obj)
        with open(sys.argv[2], 'wb') as fOut:
            fOut.write('\x03\xf3\x0d\x0a\0\0\0\0')
            marshal.dump(deob, fOut)
            print 'Done...'


if __name__ == '__main__':
    main()