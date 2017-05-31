from pyopenssl_examples.cffi.example_02_real import ffi, lib


def main():
    p = lib.getpwuid(0)
    print(ffi.string(p.pw_name))
    assert ffi.string(p.pw_name) == b'root'
    print('passed assertion')


if __name__ == '__main__':
    main()
