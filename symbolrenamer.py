'''
Script to rename all variable names in a pyc file.
This is done by recursively traversing the code objects.
'''

import marshal
import types
import sys

def rename(code_obj):
    mod_const = []
    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType):
            mod_const.append(rename(const))
        else:
            mod_const.append(const)

    argcount = code_obj.co_argcount
    nlocals = code_obj.co_nlocals
    stacksize = code_obj.co_stacksize
    flags = code_obj.co_flags
    codestring = code_obj.co_code
    constants = tuple(mod_const)
    names = code_obj.co_names
    varnames = tuple('var{}'.format(i) for i in range(len(code_obj.co_varnames)))
    filename = code_obj.co_filename
    name = code_obj.co_name  # XXX: Rename this too
    firstlineno = code_obj.co_firstlineno
    lnotab = code_obj.co_lnotab

    return types.CodeType(argcount, nlocals, stacksize, \
                          flags, codestring, constants, names, \
                          varnames, filename, name, firstlineno, lnotab)


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