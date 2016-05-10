## PjOrion Deobfuscator



PjOrion Deobfuscator is a tool (actually more than a single tool) that aims to deobfuscate [PjOrion](http://www.koreanrandom.com/forum/topic/15280-pjorion-%D1%80%D0%B5%D0%B4%D0%B0%D0%BA%D1%82%D0%B8%D1%80%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D0%B5-%D0%BA%D0%BE%D0%BC%D0%BF%D0%B8%D0%BB%D1%8F%D1%86%D0%B8%D1%8F-%D0%B4%D0%B5%D0%BA%D0%BE%D0%BC%D0%BF%D0%B8%D0%BB%D1%8F%D1%86%D0%B8%D1%8F-%D0%BE%D0%B1%D1%84/) obfuscated python scripts. 

It contains various other small utilities such as a recursive disassembler to facilitate in reverse engineering of compiled python code.

At the present, you can use the tool to generate a cfg for python bytecode.

    $ python generateCFG.py ./example/example1.pyc
    
You would get cfg images for each code objects in the pyc file.

![Example 1](/screenshots/example1.png?raw=true)    
    

### TODO
---

> - Support for **EXTENDED_ARG** opcode
> - Documentation
> - Use as a library

### LICENSE
---

PjOrion Deobfuscator is licensed under The MIT License (MIT)

Copyright (c) 2015, Extreme Coders

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

