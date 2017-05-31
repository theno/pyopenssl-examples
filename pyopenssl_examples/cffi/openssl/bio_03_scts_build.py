'''Real example (API level, out-of-line)

https://cffi.readthedocs.io/en/latest/overview.html#real-example-api-level-out-of-line
'''

from cffi import FFI


def create_ffibuilder():
    ffibuilder = FFI()

    module_name = 'pyopenssl_examples.cffi.openssl.bio_03_scts_openssl'

    # c-source code (like *.c files)
    c_source = r'''\
        #include "stdio.h"  // FILE

        #include "openssl/bio.h"
        #include "openssl/err.h"
        #include "openssl/ssl.h"
        #include "openssl/ocsp.h"

        long SSL_CTX_callback_ctrl(SSL_CTX *, int, void (*)(void));
        # define SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB       63
        void set_tlsext_status_cb(SSL_CTX *ctx,
                                  int(*cb)(struct ssl_st *, void *)) {
            // function casting in python does not work, e.g.:
            //     ffi.cast('void (*)(void)', cb)
            // so we do it here in "raw" c code
            SSL_CTX_callback_ctrl(ctx,
                                  SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB,
                                  (void (*)(void))(cb));
        }
    '''

    ffibuilder.set_source(module_name, c_source, libraries=['ssl', 'crypto'])

    # c-definitions: function declarations, types, macros, global variables
    # (like *.h files)
    c_defs = '''\
        void SSL_load_error_strings(void);
        int SSL_library_init(void);

        typedef struct ssl_method_st SSL_METHOD;
        const SSL_METHOD *SSLv23_client_method(void);

        typedef struct ssl_ctx_st SSL_CTX;
        SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);

        int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                          const char *CApath);

        void ERR_print_errors_fp(FILE *fp);

        typedef struct bio_st BIO;
        BIO *BIO_new_ssl_connect(SSL_CTX *ctx);

        typedef struct ssl_st SSL;

        SSL *SSL_new(SSL_CTX *ctx);
        long SSL_set_mode(SSL *ssl, long mode);
        # define SSL_MODE_AUTO_RETRY 0x00000004U

        # define BIO_C_GET_SSL                           110
        long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);

        long BIO_set_conn_hostname(BIO *b, char *name);

        int BIO_do_connect(BIO *b);

        long SSL_get_verify_result(const SSL *ssl);
        # define         X509_V_OK                                       0

        int BIO_puts(BIO *bp, const char *buf);
        BIO *BIO_new_fp(FILE *stream, int close_flag);
        int BIO_read(BIO *b, void *data, int dlen);
        int BIO_write(BIO *b, const void *data, int dlen);
        int BIO_free(BIO *a);
        void SSL_CTX_free(SSL_CTX *);

        // for TLS extension 18

        typedef int (*custom_ext_add_cb) (SSL *s, unsigned int ext_type,
                                          const unsigned char **out,
                                          size_t *outlen, int *al,
                                          void *add_arg);
        typedef void (*custom_ext_free_cb) (SSL *s, unsigned int ext_type,
                                            const unsigned char *out,
                                            void *add_arg);
        typedef int (*custom_ext_parse_cb) (SSL *s, unsigned int ext_type,
                                            const unsigned char *in,
                                            size_t inlen, int *al,
                                            void *parse_arg);
        int SSL_CTX_add_client_custom_ext(SSL_CTX *ctx, unsigned int ext_type,
                                          custom_ext_add_cb add_cb,
                                          custom_ext_free_cb free_cb,
                                          void *add_arg,
                                          custom_ext_parse_cb parse_cb,
                                          void *parse_arg);

        extern "Python" static int serverinfo_cli_parse_cb(SSL *s,
                                                           unsigned int ext_type,
                                                           const unsigned char *in,
                                                           size_t inlen,
                                                           int *al, void *arg);

        // for OCSP response

        long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);
        # define SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE     65
        # define TLSEXT_STATUSTYPE_ocsp 1
        # define SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP        70

        extern "Python" static int ocsp_resp_cb(SSL *s, void *arg);
        # define SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB       63
        long SSL_CTX_callback_ctrl(SSL_CTX *, int, void (*)(void));

        void set_tlsext_status_cb(SSL_CTX *ctx,
                                  int(*cb)(struct ssl_st *, void *));
    '''

    ffibuilder.cdef(c_defs)

    return ffibuilder


def main():
    ffibuilder = create_ffibuilder()
    ffibuilder.compile(verbose=True)


if __name__ == '__main__':
    main()
