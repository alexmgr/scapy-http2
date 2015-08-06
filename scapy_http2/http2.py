#! -*- coding: utf-8 -*-

import collections
import random
import struct

from scapy.fields import ByteEnumField, ByteField, ConditionalField, FieldLenField, FlagsField, IntEnumField, IntField, \
    LenField, PacketListField, ShortEnumField, StrField, StrFixedLenField, StrLenField
from scapy.layers.inet import TCP
from scapy.packet import bind_layers, Packet, Padding


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


class HTTP2Frame(Packet):
    name = "HTTP2 Frame Header"
    fields_desc = [ByteLenField("length", None, width=3),
                   ByteEnumField("type", HTTP2FrameTypes.DATA, HTTP2_FRAME_TYPES),
                   FlagsField("flags", 0, 8, HTTP2_FLAGS.values()),
                   IntField("stream", 0)]


class HTTP2PaddedFrame(Packet):

    def pre_dissect(self, s):
        if self.underlayer is not None and has_flag_set(self.underlayer, HTTP2Flags.PADDED):
            padding_length = ord(s[0])
            self.add_payload(Padding(load=s[-padding_length:]))
            # self.fields["padding"] = s[-padding_length:]
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
                   StrField("data", ":method = GET\r\n:scheme = https\r\n:path = /\r\n") ]


class HTTP2Headers(HTTP2PaddedFrame):
    name = "HTTP2 %s Frame" % HTTP2_FRAME_TYPES[HTTP2FrameTypes.HEADERS]
    fields_desc = [ConditionalField(LenField("padding_length", None, fmt="B"), underlayer_has_padding_flag_set),
                   ConditionalField(IntField("dependency_stream", 0), underlayer_has_priority_flag_set),
                   ConditionalField(ByteField("weight", 0), underlayer_has_priority_flag_set),
                   # Encoding for => Host: 127.0.0.1
                   StrField("headers", "f\x87\x08\x9d\\\x0b\x81p\xff") ]


class HTTP2Priority(Packet):
    name = "HTTP2 %s Frame" % HTTP2_FRAME_TYPES[HTTP2FrameTypes.PRIORITY]
    fields_desc = [IntField("dependency_stream", 0),
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
                   IntField("promised_stream", 0),
                   StrField("headers", "f\x87\x08\x9d\\\x0b\x81p\xff")]


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
    fields_desc = [StrField("headers", "f\x87\x08\x9d\\\x0b\x81p\xff")]


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
        while pos < len(raw_bytes) - frame_header_len:
            payload_len = frame(raw_bytes[pos: pos + frame_header_len]).length
            payload = frame(raw_bytes[pos: pos + frame_header_len + payload_len])
            # Populate our list of found frames
            frames.append(payload)
            pos += (frame_header_len + payload.length)
        self.fields["frames"] = frames
        return raw_bytes[pos:]


def pack_headers(encoder, headers):
    return encoder.encode(headers)

def unpack_headers(decoder, str_):
    return decoder.decode(str_)

def set_msb(stream_id):
    return stream_id | 0x80000000

def unset_msb(stream_id):
    return stream_id & ~0x80000000

def toggle_msb(stream_id):
    return stream_id ^ 0x80000000

def generate_stream_id():
    return unset_msb(random.randint(0, 2**32 -1))

set_dependency_e_flag = set_msb
unset_dependency_e_flag = unset_msb
toggle_dependency_e_flag = toggle_msb

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
