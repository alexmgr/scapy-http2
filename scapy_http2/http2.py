#! -*- coding: utf-8 -*-

import base64
import collections
import random
import socket
import ssl
import struct
import sys
import urllib
import urlparse
import warnings

from scapy.fields import BitField, ByteEnumField, ByteField, ConditionalField, FlagsField, IntEnumField, IntField, \
    LenField, PacketListField, ShortEnumField, StrField, StrFixedLenField
from scapy.layers.inet import TCP
from scapy.packet import bind_layers, Packet, Padding


H2_ALPN_IDS = ["h2"]


class ByteLenField(LenField):
    def __init__(self, name, default=None, fmt="I", width=None):
        self.name = name
        self.width = width
        self.default = self.any2i(None, default)
        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!" + fmt
        self.size = self.width or struct.calcsize(self.fmt)
        # Scapy uses old style classes. No super() here
        # super(ByteLenField, self).__init__(name, default, fmt)
        LenField.__init__(self, name, default, fmt)

    def addfield(self, pkt, s, val):
        pack = struct.pack(self.fmt, self.i2m(pkt, val))
        if self.width:
            pack = pack[len(pack) - self.width:]
        return s + pack

    def getfield(self, pkt, s):
        padded_data = "\x00" * (struct.calcsize(self.fmt) - self.size) + s[:self.size]
        return s[self.size:], self.m2i(pkt, struct.unpack(self.fmt, padded_data)[0])


class Dict2Enum(object):
    def __init__(self, entries):
        entries = dict((v.replace(" ", "_").upper(), k) for k, v in entries.iteritems())
        self.__dict__.update(entries)


HTTP2_FRAME_TYPES = {0x00: "DATA",
                     0x01: "HEADERS",
                     0x02: "PRIORITY",
                     0x03: "RST_STREAM",
                     0x04: "SETTINGS",
                     0x05: "PUSH_PROMISE",
                     0x06: "PING",
                     0x07: "GOAWAY",
                     0x08: "WINDOW_UPDATE",
                     0x09: "CONTINUATION"}

HTTP2FrameTypes = Dict2Enum(HTTP2_FRAME_TYPES)

HTTP2_FLAGS = collections.OrderedDict(((0x01, "ACK"),
                                       (0x02, "UNUSED_2"),
                                       (0x04, "END_HEADERS"),
                                       (0x08, "PADDED"),
                                       (0x10, "UNUSED_5"),
                                       (0x20, "PRIORITY"),
                                       (0x40, "UNUSED_7"),
                                       (0x80, "UNUSED_8")))

HTTP2Flags = Dict2Enum(HTTP2_FLAGS)
HTTP2Flags.END_STREAM = 0x1

HTTP2_ERROR_CODES = {0x00: "NO_ERROR",
                     0x01: "PROTOCOL_ERROR",
                     0x02: "INTERNAL_ERROR",
                     0x03: "FLOW_CONTROL_ERROR",
                     0x04: "SETTINGS_TIMEOUT",
                     0x05: "STREAM_CLOSED",
                     0x06: "FRAME_SIZE_ERROR",
                     0x07: "REFUSED_STREAM",
                     0x08: "CANCEL",
                     0x09: "COMPRESSION_ERROR",
                     0x0a: "CONNECT_ERROR",
                     0x0b: "ENHANCE_YOUR_CALM",
                     0x0c: "INADEQUATE_SECURITY",
                     0x0d: "HTTP_1_1_REQUIRED"}

HTTP2ErrorCodes = Dict2Enum(HTTP2_ERROR_CODES)

HTTP2_SETTING_IDS = {0x01: "SETTINGS_HEADER_TABLE_SIZE",
                     0x02: "SETTINGS_ENABLE_PUSH",
                     0x03: "SETTINGS_MAX_CONCURRENT_STREAMS",
                     0x04: "SETTINGS_INITIAL_WINDOW_SIZE",
                     0x05: "SETTINGS_MAX_FRAME_SIZE",
                     0x06: "SETTINGS_MAX_HEADER_LIST_SIZE"}

HTTP2SettingIds = Dict2Enum(HTTP2_SETTING_IDS)


def has_flag_set(pkt, flag):
    flag_index = HTTP2_FLAGS.keys().index(flag)
    return True if pkt.haslayer(HTTP2Frame) and (pkt[HTTP2Frame].flags & flag) >> flag_index == 1 else False


class HTTP1Packet(Packet):
    name = "HTTP1 Packet"
    MAGIC = "HTTP/1.1"
    DELIMITER = "\r\n"
    MAGIC_END = DELIMITER * 2
    UPGRADE_MAGIC = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
    fields_desc = [StrField("data", UPGRADE_MAGIC)]


class HTTP2Preface(Packet):
    name = "HTTP2 Preface"
    MAGIC = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    fields_desc = [StrFixedLenField("preface", MAGIC, len(MAGIC))]


class HTTP2Frame(Packet):
    name = "HTTP2 Frame Header"
    fields_desc = [ByteLenField("length", None, width=3),
                   ByteEnumField("type", HTTP2FrameTypes.DATA, HTTP2_FRAME_TYPES),
                   FlagsField("flags", 0, 8, HTTP2_FLAGS.values()),
                   BitField("R", 0, 1),
                   BitField("stream", 0, 31)]


class HTTP2PaddedFrame(Packet):

    def pre_dissect(self, s):
        if self.underlayer is not None and has_flag_set(self.underlayer, HTTP2Flags.PADDED):
            padding_length = ord(s[0])
            self.add_payload(Padding(load=s[-padding_length:]))
            s = s[:-padding_length]
        return s


def underlayer_has_flag_set(pkt, flag):
    flag_index = HTTP2_FLAGS.keys().index(flag)
    return True if pkt.underlayer is not None and (pkt.underlayer.flags & flag) >> flag_index == 1 else False

underlayer_has_padding_flag_set = lambda pkt: underlayer_has_flag_set(pkt, HTTP2Flags.PADDED)
underlayer_has_priority_flag_set = lambda pkt: underlayer_has_flag_set(pkt, HTTP2Flags.PRIORITY)


class HTTP2Data(HTTP2PaddedFrame):
    name = "HTTP2 %s Frame" % HTTP2_FRAME_TYPES[HTTP2FrameTypes.DATA]
    fields_desc = [ConditionalField(LenField("padding_length", None, fmt="B"), underlayer_has_padding_flag_set),
                   StrField("data", ":method = GET\r\n:scheme = https\r\n:path = /\r\n")]


class HTTP2Headers(HTTP2PaddedFrame):
    name = "HTTP2 %s Frame" % HTTP2_FRAME_TYPES[HTTP2FrameTypes.HEADERS]
    fields_desc = [ConditionalField(LenField("padding_length", None, fmt="B"), underlayer_has_padding_flag_set),
                   ConditionalField(BitField("E", 0, 1), underlayer_has_priority_flag_set),
                   ConditionalField(BitField("stream_dependency", 0, 31), underlayer_has_priority_flag_set),
                   ConditionalField(ByteField("weight", 0), underlayer_has_priority_flag_set),
                   # Encoding for => :method: GET, :scheme: https, :path: /, host: localhost
                   StrField("headers", "\x87\x84f\x86\xa0\xe4\x1d\x13\x9d\t\x82")]


class HTTP2Priority(Packet):
    name = "HTTP2 %s Frame" % HTTP2_FRAME_TYPES[HTTP2FrameTypes.PRIORITY]
    fields_desc = [BitField("E", 0, 1),
                   BitField("stream_dependency", 0, 31),
                   ByteField("weight", 0)]


class HTTP2RstStream(Packet):
    name = "HTTP2 %s Frame" % HTTP2_FRAME_TYPES[HTTP2FrameTypes.RST_STREAM]
    fields_desc = [IntEnumField("error_code", HTTP2ErrorCodes.NO_ERROR, HTTP2_ERROR_CODES)]


class HTTP2Setting(Packet):
    name = "HTTP2 Setting"
    fields_desc = [ShortEnumField("id", HTTP2SettingIds.SETTINGS_HEADER_TABLE_SIZE, HTTP2_SETTING_IDS),
                   IntField("value", 4096)]


class HTTP2Settings(Packet):
    name = "HTTP2 %s Frame" % HTTP2_FRAME_TYPES[HTTP2FrameTypes.SETTINGS]
    fields_desc = [PacketListField("settings", None, HTTP2Setting)]

    def do_dissect(self, s):
        pos = 0
        setting_len = len(HTTP2Setting())
        settings = []
        while pos < len(s):
            if len(s[pos: pos + setting_len]) == setting_len:
                setting = HTTP2Setting(s[pos: pos + setting_len])
                # Populate our list of found settings
                settings.append(setting)
                # Move to the next settings
                pos += setting_len
            # Setting is too small too parse, pass it for further processing
            else:
                break
        self.fields["settings"] = settings
        return s[pos:]


class HTTP2PushPromise(HTTP2PaddedFrame):
    name = "HTTP2 %s Frame" % HTTP2_FRAME_TYPES[HTTP2FrameTypes.PUSH_PROMISE]
    fields_desc = [ConditionalField(LenField("padding_length", None, fmt="B"), underlayer_has_padding_flag_set),
                   BitField("R", 0, 1),
                   BitField("promised_stream", 0, 31),
                   StrField("headers", "\x87\x84f\x86\xa0\xe4\x1d\x13\x9d\t\x82")]


class HTTP2Ping(Packet):
    name = "HTTP2 %s Frame" % HTTP2_FRAME_TYPES[HTTP2FrameTypes.PING]
    fields_desc = [StrFixedLenField("data", "ping" * 2, 8)]


class HTTP2GoAway(Packet):
    name = "HTTP2 %s Frame" % HTTP2_FRAME_TYPES[HTTP2FrameTypes.GOAWAY]
    fields_desc = [IntField("last_stream", 0),
                   IntEnumField("error_code", HTTP2ErrorCodes.NO_ERROR, HTTP2_ERROR_CODES),
                   StrField("debug_data", "")]


class HTTP2WindowUpdate(Packet):
    name = "HTTP2 %s Frame" % HTTP2_FRAME_TYPES[HTTP2FrameTypes.WINDOW_UPDATE]
    fields_desc = [IntField("window_size", 65535)]


class HTTP2Continuation(Packet):
    name = "HTTP2 %s Frame" % HTTP2_FRAME_TYPES[HTTP2FrameTypes.CONTINUATION]
    fields_desc = [StrField("headers", "\x87\x84f\x86\xa0\xe4\x1d\x13\x9d\t\x82")]


class HTTP2(Packet):
    name = "HTTP2"
    fields_desc = [PacketListField("frames", None, HTTP2Frame)]

    @classmethod
    def from_frames(cls, records):
        pkt_str = "".join(list(map(str, records)))
        return cls(pkt_str)

    def do_dissect(self, raw_bytes):
        pos = 0
        frame = HTTP2Frame
        frame_header_len = len(frame())

        frames = []
        if raw_bytes.startswith(HTTP1Packet.MAGIC):
            try:
                http1_packet_end = raw_bytes.index(HTTP1Packet.MAGIC_END) + len(HTTP1Packet.MAGIC_END)
                frames.append(HTTP1Packet(raw_bytes[:http1_packet_end]))
                raw_bytes = raw_bytes[http1_packet_end:]
            # Can't find the end of the HTTP1 packet. Parse as HTTP2
            except ValueError:
                pass

        while pos <= len(raw_bytes) - frame_header_len:
            preface = None
            # If we have a HTTP2 Magic, parse it and remove it from bytes
            if raw_bytes[pos: pos + len(HTTP2Preface.MAGIC)] == HTTP2Preface.MAGIC:
                preface = HTTP2Preface(raw_bytes[pos: pos + len(HTTP2Preface.MAGIC)])
                pos += len(HTTP2Preface.MAGIC)
            payload_len = frame(raw_bytes[pos: pos + frame_header_len]).length or 0
            payload = frame(raw_bytes[pos: pos + frame_header_len + payload_len])
            # Populate our list of found frames
            if preface is not None:
                frames.append(preface / payload)
            else:
                frames.append(payload)
            pos += (frame_header_len + (payload.length or 0))
        self.fields["frames"] = frames
        return raw_bytes[pos:]


class HTTP2Socket(object):
    def __init__(self, socket_):
        if socket_ is None:
            raise ValueError("Socket object required")
        self.socket_ = socket_
        self.history = []

    def __getattr__(self, attr):
        try:
            super(HTTP2Socket, self).__getattr__()
        except AttributeError:
            return getattr(self.socket_, attr)

    def _build_http1_request(self, prepared_request):
        parsed_url = urlparse.urlparse(prepared_request.url)
        if "Host".lower() not in map(lambda x: x.lower(), prepared_request.headers.keys()):
            prepared_request.headers["Host"] = parsed_url.netloc
        request = "%s\r\n%s\r\n\r\n%s" % ("%s %s HTTP/1.1" % (prepared_request.method, prepared_request.path_url),
                                          "\r\n".join("%s: %s" % (k, v) for k, v in prepared_request.headers.items()),
                                          prepared_request.body or "")
        return request

    def send_preface(self, settings=[]):
        req = HTTP2.from_frames([HTTP2Preface(),
                                 HTTP2Frame() / HTTP2Settings(settings=settings)])
        self.sendall(req)
        return self.recvall()

    def send_upgrade(self, prepared_request):
        default_settings = HTTP2Settings(settings=[HTTP2Setting(id=HTTP2SettingIds.SETTINGS_MAX_CONCURRENT_STREAMS,
                                                                value=100)])
        prepared_headers = map(lambda x: x.lower(), prepared_request.headers.keys())
        if "Connection".lower() not in prepared_headers:
            prepared_request.headers["Connection"] = "Upgrade, HTTP2-Settings"
        if "Upgrade".lower() not in prepared_headers:
            prepared_request.headers["Upgrade"] = "h2c"
        if "HTTP2-Settings".lower() not in prepared_headers:
            prepared_request.headers["HTTP2-Settings"] = urllib.quote(base64.b64encode(str(default_settings)))
        self.sendall(self._build_http1_request(prepared_request))
        return self.recvall()

    def sendall(self, pkt):
        self.socket_.sendall(str(pkt))
        self.history.append(pkt)

    def recvall(self, size=8192):
        import ssl
        resp = []
        while True:
            try:
                data = self.socket_.recv(size)
                if not data:
                    break
                resp.append(data)
            except socket.timeout:
                break
            except ssl.SSLError:
                break
        frames = HTTP2("".join(resp))
        self.history.append(frames)
        return frames

def tls_connect(tls_socket, host, force_npn=False):
    missing_alpn = True
    connection_succeeded = False
    try:
        tls_socket.context.set_alpn_protocols(H2_ALPN_IDS)
        missing_alpn = False
        connection_succeeded = True
    except AttributeError:
        warnings.warn("Python missing ALPN support. Found %s.%s.%s, require 2.7.10" %
                      (sys.version_info.major, sys.version_info.minor, sys.version_info.micro))
    except NotImplementedError:
        warnings.warn("Openssl missing ALPN support. Found %s, require 1.0.2" %
                      ".".join(map(str, ssl.OPENSSL_VERSION_INFO[:3])))

    if missing_alpn or force_npn:
        warnings.warn("Attempting to use NPN. Most implementations should not work, but nghttp2 does")
        try:
            tls_socket.context.set_npn_protocols(H2_ALPN_IDS)
            connection_succeeded = True
        except (AttributeError, NotImplementedError):
            raise RuntimeError("Python or Openssl missing NPN support")

    if connection_succeeded:
        try:
            tls_socket.connect(host)
        except (socket.error, ssl.socket_error):
            connection_succeeded = False
    return connection_succeeded

def wrap_tls_socket(tls_socket):
    if tls_socket.selected_npn_protocol() in H2_ALPN_IDS or tls_socket.selected_alpn_protocol() in H2_ALPN_IDS:
        return HTTP2Socket(tls_socket)
    else:
        raise RuntimeError("ALPN negotiation failed")

def pack_headers(encoder, headers):
    return encoder.encode(headers)

def unpack_headers(decoder, str_):
    return decoder.decode(str_)

def generate_stream_id():
    return random.randint(0, 2**31 - 1)

def get_stream_ids(start_id=3, end_id=2**31 - 1):
    for id_ in xrange(start_id, end_id, 2):
        yield id_

def get_client_stream_ids(start_id=3, end_id=2**31 - 1):
    if start_id % 2 == 0:
        raise ValueError("Client stream ids must be odd")
    else:
        return get_stream_ids(start_id, end_id)

def get_server_stream_ids(start_id=2, end_id=2**31 - 1):
    if start_id % 2 != 0:
        raise ValueError("Server stream ids must be even")
    else:
        return get_stream_ids(start_id, end_id)

bind_layers(TCP, HTTP2Frame, dport=443)
bind_layers(TCP, HTTP2Frame, sport=443)
bind_layers(HTTP2Frame, HTTP2Data, type=HTTP2FrameTypes.DATA)
bind_layers(HTTP2Frame, HTTP2Headers, type=HTTP2FrameTypes.HEADERS)
bind_layers(HTTP2Frame, HTTP2Priority, type=HTTP2FrameTypes.PRIORITY)
bind_layers(HTTP2Frame, HTTP2RstStream, type=HTTP2FrameTypes.RST_STREAM)
bind_layers(HTTP2Frame, HTTP2Settings, type=HTTP2FrameTypes.SETTINGS)
bind_layers(HTTP2Frame, HTTP2PushPromise, type=HTTP2FrameTypes.PUSH_PROMISE)
bind_layers(HTTP2Frame, HTTP2Ping, type=HTTP2FrameTypes.PING)
bind_layers(HTTP2Frame, HTTP2GoAway, type=HTTP2FrameTypes.GOAWAY)
bind_layers(HTTP2Frame, HTTP2WindowUpdate, type=HTTP2FrameTypes.WINDOW_UPDATE)
bind_layers(HTTP2Frame, HTTP2Continuation, type=HTTP2FrameTypes.CONTINUATION)
