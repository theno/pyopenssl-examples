'''Real example (API level, out-of-line)

https://cffi.readthedocs.io/en/latest/overview.html#real-example-api-level-out-of-line
'''

from cffi import FFI


def create_ffibuilder():
    ffibuilder = FFI()

    module_name = 'pyopenssl_examples.cffi.openssl.bio_01_connect_openssl'

    # c-source code (like *.c files)
    c_source = r'''\
        #include "stdio.h"  // FILE

        #include "openssl/bio.h"
        #include "openssl/err.h"
        #include "openssl/ssl.h"
    '''

    ffibuilder.set_source(module_name, c_source, libraries=['ssl', 'crypto'])

    # c-definitions: function declarations, types, macros, global variables
    # (like *.h files)
    c_defs = '''\
        typedef struct bio_st BIO;
        BIO *BIO_new_connect(const char *host_port);
        int BIO_do_connect(BIO *b);
        int BIO_puts(BIO *bp, const char *buf);
        BIO *BIO_new_fp(FILE *stream, int close_flag);
        int BIO_read(BIO *b, void *data, int dlen);
        int BIO_write(BIO *b, const void *data, int dlen);
        int BIO_free(BIO *a);
    '''

    ffibuilder.cdef(c_defs)

    return ffibuilder


def main():
    ffibuilder = create_ffibuilder()
    ffibuilder.compile(verbose=True)


if __name__ == '__main__':
    main()
