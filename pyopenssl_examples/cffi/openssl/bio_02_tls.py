'''Send an HTTPS request to hostname (port 443) and print the reply to stdout.

OpenSSL is used directly, not via PyOpenSSL.

The program flow follows `tls-connect.c`.
'''

import argparse
import sys

from pyopenssl_examples.cffi.openssl.bio_02_tls_openssl import ffi, lib


def BIO_get_ssl(cbio, sslp):
    return lib.BIO_ctrl(cbio, lib.BIO_C_GET_SSL, 0, sslp)


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
        sys.exit(1)

    if not lib.SSL_CTX_load_verify_locations(
            ctx,
            b'/etc/ssl/certs/ca-certificates.crt',
            ffi.NULL):
        sys.stderr.write('Error loading trust store into SSL context\n')
        lib.ERR_print_errors_fp(sys.stderr)

    # Set up the SSL connection

    cbio = lib.BIO_new_ssl_connect(ctx)

    # FIXME does this work? make sense? verify always passes
    ssl = lib.SSL_new(ctx)
    BIO_get_ssl(cbio, ssl)
    # Set flag SSL_MODE_AUTO_RETRY
    lib.SSL_set_mode(ssl, lib.SSL_MODE_AUTO_RETRY)

    # Connect to server <hostname>
    name = '{hostname}:{port}'.format(hostname=hostname, port='https')
    name_bytes = name.encode('ascii')

    lib.BIO_set_conn_hostname(cbio, name_bytes)

    if lib.BIO_do_connect(cbio) <= 0:
        sys.stderr.write('Error connecting to server\n')
        sys.exit(1)

    # Check the certificate

    if lib.SSL_get_verify_result(ssl) != lib.X509_V_OK:
        sys.stderr.write(
            'Certificate verification error: {err}\n'.format(
                err=lib.SSL_get_verify_result(ssl)))
        # sys.exit(1)

    # send HTTP request to the server <hostname>

    req = 'GET / HTTP/1.1\x0D\x0AHost: %s\x0D\x0AConnection: ' \
          'Close\x0D\x0A\x0D\x0A' % hostname
    lib.BIO_puts(cbio, req.encode('ascii'))

    # read HTTP response from server and print to stdout

    # output bio
    out = lib.BIO_new_fp(sys.stdout, 0)

    tmpbuf_len = 1024
    tmpbuf = tmpbuf_len * b'\0'  # c-style way to allocate memory

    while True:
        length = lib.BIO_read(cbio, tmpbuf, tmpbuf_len)
        if length <= 0:
            break
        lib.BIO_write(out, tmpbuf, length)
        break  # to print complete answer comment out this line

    # close TCP/IP connection and free used BIOs

    lib.BIO_free(cbio)
    lib.SSL_CTX_free(ctx)
    lib.BIO_free(out)

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
