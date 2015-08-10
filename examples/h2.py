# -*- coding: utf-8 -*-

# import socket
import ssl
from hpack import hpack

from scapy_http2.http2 import *


encoder = hpack.Encoder()
decoder = hpack.Decoder()

socket_ = socket.socket()
ssl_socket = ssl.SSLSocket(socket_)
ssl_socket.context.set_alpn_protocols(["h2"])
ssl_socket.connect(("http2.golang.org", 443))
ssl_socket.settimeout(2)
# ssl_socket.connect(("http2.akamai.com", 443))
print(ssl_socket.selected_alpn_protocol())

http2_socket = HTTP2Socket(ssl_socket)


req = HTTP2.from_frames([HTTP2Preface(),
                         HTTP2Frame() / HTTP2Settings(),
                         HTTP2Frame(flags=(HTTP2Flags.END_HEADERS), stream=0x5) /
                         HTTP2Headers(headers=pack_headers(encoder, {":method": "GET", ":scheme": "https", ":path": "/reqinfo", "host": "http2.golang.org"}))
                         ])
http2_socket.sendall(req)
resp = http2_socket.recvall()
resp.show()



req = HTTP2.from_frames([HTTP2Frame(flags=HTTP2Flags.ACK, stream=0x0) / HTTP2Settings(),
                         HTTP2Frame(stream=0x0) / HTTP2GoAway()])
http2_socket.sendall(req)
resp = http2_socket.recvall()
resp.show()

ssl_socket.close()