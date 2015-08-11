#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

from hpack import hpack

try:
    from scapy.layers.http2 import *
except ImportError:
    import os
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    from scapy_http2.http2 import *


def prepare_parser():
    parser = argparse.ArgumentParser(description="A simple HTTP2 GET client")
    parser.add_argument("host", help="Host to connect to")
    parser.add_argument("-p", "--port", help="Port to connect to. Default is 443", type=int, default=443)
    parser.add_argument("-c", "--cleartext", help="Use h2c instead of h2", action="store_true")
    parser.add_argument("-t", "--timeout", help="Socket timeout. Default is 0.5 seconds", type=float, default=0.5)
    parser.add_argument("-r", "--resource", help="The path to the page to retrieve. Default is /", default="/")
    parser.add_argument("-n", "--npn", help="Force the use of NPN instead of ALPN", action="store_true")
    return parser

if __name__ == "__main__":
    parser = prepare_parser()
    args = parser.parse_args()

    host = (args.host, args.port)
    scheme = "http" if args.cleartext else "https"

    encoder = hpack.Encoder()

    socket_ = socket.socket()

    if args.cleartext:
        try:
            socket_.connect(host)
            socket_.settimeout(args.timeout)
        except socket.error:
            parser.exit(2, "Failed TCP connection")
        http2_socket = HTTP2Socket(socket_)
    else:
        tls_socket = ssl.SSLSocket(socket_)
        tls_socket.settimeout(args.timeout)
        if tls_connect(tls_socket, host, args.npn):
            http2_socket = wrap_tls_socket(tls_socket)
        else:
            parser.exit(2, "Failed TLS connection")

    resp = http2_socket.send_preface()

    if resp.haslayer(HTTP2Settings):
        req = HTTP2.from_frames([HTTP2Frame(flags=HTTP2Flags.ACK) / HTTP2Settings(),
                                 HTTP2Frame(flags=HTTP2Flags.ACK, stream=0x5) /
                                 HTTP2Headers(headers=pack_headers(
                                     encoder, {":method": "GET", ":scheme": scheme, ":path": args.resource})),
                                 HTTP2Frame(flags=HTTP2Flags.END_HEADERS, stream=0x5) /
                                 HTTP2Continuation(headers=pack_headers(encoder, {"host": host[0]}))])
        http2_socket.sendall(req)
        resp = http2_socket.recvall()
        resp.show()
    else:
        print("Received server preface without settings")
        resp.show()

    if not args.cleartext:
        tls_socket.close()
    socket_.close()
