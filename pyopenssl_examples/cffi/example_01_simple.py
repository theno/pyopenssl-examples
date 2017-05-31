'''
Simple example (ABI level, in-line)

https://cffi.readthedocs.io/en/latest/overview.html#simple-example-abi-level-in-line
'''

from cffi import FFI


def main():
    ffi = FFI()
    ffi.cdef('''
    int printf(const char *format, ...);  // copy-pasted from `man 3 printf`
''')

    # load the entire C namespace
    C = ffi.dlopen(None)

    # equivalent to C code: char arg[] = "world";
    arg = ffi.new('char[]', b'world')

    # call printf
    res = C.printf(b'hi there, %s.\n', arg)

    print("return value: %s" % res)


if __name__ == '__main__':
    main()
