'''Send an HTTP request to hostname (port 80) and print the reply to stdout.

OpenSSL is used directly, not via PyOpenSSL.

This is a rewrite step-by-step of openssl-examples/bio-connect.c in python using
OpenSSL in a very c-style manner which is not a good practice.  But it helps to
understand how OpenSSl works -- and it works.
'''

import argparse
import sys

from pyopenssl_examples.cffi.openssl.bio_01_connect_openssl import lib


def bio_connect(hostname):
    '''Send an HTTP request to hostname (port 80) and print the reply to stdout.

    It follows the example of `man BIO_s_connect` (version: OpenSSL-1.1.0).
    '''

    # create and setup the TCP/IP connection

    port = 'http'
    name = "%s:%s" % (hostname, port)

    # connection bio
    cbio = lib.BIO_new_connect(name.encode('ascii'))

    if lib.BIO_do_connect(cbio) <= 0:
        sys.stderr.write('Error connecting to server\n')
        sys.exit(1)

    # send HTTP request to the server <hostname>

    req = 'GET / HTTP/1.1\x0D\x0AHost: %s\x0D\x0AConnection: ' \
          'Close\x0D\x0A\x0D\x0A' % hostname
    lib.BIO_puts(cbio, req.encode('ascii'))

    # read HTTP response from server and print to stdout

    # output bio
    out = lib.BIO_new_fp(sys.stdout, 0)

    tmpbuf_len = 1024
    tmpbuf = tmpbuf_len * b'\0'  # c-style way to allocate memory
    # tmpbuf = 10 * b'\0'  # `fab run --hide=stdout` --> "Segmentation fault..."

    while True:
        length = lib.BIO_read(cbio, tmpbuf, tmpbuf_len)
        if length <= 0:
            break
        lib.BIO_write(out, tmpbuf, length)
        break  # to print complete answer comment out this line

    # close TCP/IP connection and free used BIOs

    lib.BIO_free(cbio)
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
