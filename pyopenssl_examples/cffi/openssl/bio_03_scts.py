'''Gather SCTs by TLS handshake via extension 18 and from OCSP response.

OpenSSL is used directly, not via PyOpenSSL.

The program flow follows `tls-connect.c`; the callback mechanism was cribbed by
the `s_client` implementation of OpenSSL.
'''

import argparse
import sys

from pyopenssl_examples.cffi.openssl.bio_03_scts_openssl import ffi, lib


def BIO_get_ssl(cbio, sslp):
    return lib.BIO_ctrl(cbio, lib.BIO_C_GET_SSL, 0, sslp)


def SSL_CTX_set_tlsext_status_cb(ctx, ocsp_resp_cb):
    lib.set_tlsext_status_cb(ctx, ocsp_resp_cb)
    return 1  # True


def SSL_get_tlsext_status_ocsp_resp(ssl, arg):
    lib.SSL_ctrl(ssl,
                 lib.SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP,
                 0,
                 ffi.cast('void *', arg))


def SSL_set_tls_ext_status_type(ssl, _type):
    lib.SSL_ctrl(ssl, lib.SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE, _type, ffi.NULL)


@ffi.def_extern()
def ocsp_resp_cb(ssl, arg):
    print('####\nH I H I\n----')
    print('ssl: ')
    print(ssl)
    print('arg: ')
    print(arg)
    return 1  # True


@ffi.def_extern()
def serverinfo_cli_parse_cb(ssl, ext_type, _in, inlen, al, arg):
    print('\nserverinfo_cli_parse_cb(')
    sys.stdout.write('  ext_type=')
    sys.stdout.write(str(ext_type))
    sys.stdout.write(',\n  ')
    sys.stdout.write('inlen=')
    sys.stdout.write(str(inlen))
    sys.stdout.write(',\n  ')
    sys.stdout.write('_in=')
    sys.stdout.write(str(bytes(ffi.buffer(_in, inlen))))
    print('\n  ...)')
    return 1  # True


def bio_connect(hostname):
    '''Send an HTTP request to hostname (port 80) and print the reply to stdout.

    It follows the example of `man BIO_s_connect` (version: OpenSSL-1.1.0).
    '''
    # Set up the OpenSSL library
    lib.SSL_load_error_strings()
    lib.SSL_library_init()

    # Create SSL context structure and load the trust store
    # (accepted root ca-certificates)

    ctx = lib.SSL_CTX_new(lib.SSLv23_client_method())
    if not ctx:
        sys.stderr.write('Error creating SSL context\n')
        lib.ERR_print_errors_fp(sys.stderr)
        sys.exit(1)

    if not lib.SSL_CTX_load_verify_locations(
            ctx,
            b'/etc/ssl/certs/ca-certificates.crt',
            ffi.NULL):
        sys.stderr.write('Error loading trust store into SSL context\n')
        lib.ERR_print_errors_fp(sys.stderr)

    if not lib.SSL_CTX_add_client_custom_ext(ctx,
                                             18,
                                             ffi.NULL, ffi.NULL, ffi.NULL,
                                             lib.serverinfo_cli_parse_cb,
                                             ffi.NULL):
        sys.stderr.write('Unable to add custom extension 18\n')
        lib.ERR_print_errors_fp(sys.stderr)
        sys.exit(1)

    # Set up the SSL connection

    cbio = lib.BIO_new_ssl_connect(ctx)

    # FIXME does this work? make sense? verify always passes
    ssl = lib.SSL_new(ctx)
    BIO_get_ssl(cbio, ssl)
    # Set flag SSL_MODE_AUTO_RETRY
    lib.SSL_set_mode(ssl, lib.SSL_MODE_AUTO_RETRY)

    SSL_set_tls_ext_status_type(ssl, lib.TLSEXT_STATUSTYPE_ocsp)
    if not SSL_CTX_set_tlsext_status_cb(ctx, lib.ocsp_resp_cb):
        sys.stderr.write('Unable to add ocsp callback\n')
        lib.ERR_print_errors_fp(sys.stderr)
        sys.exit(1)

    # Connect to server <hostname>
    name = '{hostname}:{port}'.format(hostname=hostname, port='https')
    name_bytes = name.encode('ascii')

    lib.BIO_set_conn_hostname(cbio, name_bytes)

    if lib.BIO_do_connect(cbio) <= 0:
        sys.stderr.write('Error connecting to server\n')
        sys.exit(1)

    print('done: BIO_do_connect(cbio)')

    resp = ffi.new('char **')
    res = SSL_get_tlsext_status_ocsp_resp(ssl, resp)
    print(res)

    # close TCP/IP connection and free used BIOs

    # TODO DEBUG
#    import time
#    time.sleep(2)

    lib.BIO_free(cbio)
    lib.SSL_CTX_free(ctx)

    return 0


def create_parser():
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('hostname',
                        help='host name of the server '
                             "(example: 'editorconfig.org')")
    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()
    bio_connect(args.hostname)


if __name__ == '__main__':
    main()
