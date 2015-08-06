#! -*- coding: utf-8 -*-

import collections
import os
import random
import struct

from scapy.fields import ByteEnumField, ByteField, ConditionalField, FieldLenField, FlagsField, LenField, \
    PacketListField, StrField, StrFixedLenField, StrLenField
from scapy.layers.inet import TCP
from scapy.packet import bind_layers, Packet


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

HTTP2_FLAGS = collections.OrderedDict(((0x01, "END_STREAM"),
                                       (0x02, "UNUSED_2"),
                                       (0x04, "END_HEADERS"),
                                       (0x08, "PADDED"),
                                       (0x10, "UNUSED_5"),
                                       (0x20, "PRIORITY"),
                                       (0x40, "UNUSED_7"),
                                       (0x80, "UNUSED_8")))

HTTP2Flags = Dict2Enum(HTTP2_FLAGS)

def has_flag_set(pkt, flag):
    flag_index = HTTP2_FLAGS.keys().index(flag)
    return True if pkt.haslayer(HTTP2Frame) and (pkt[HTTP2Frame].flags & flag) >> flag_index == 1 else False

class HTTP2Frame(Packet):
    name = "HTTP2 Frame"
    fields_desc = [ByteLenField("length", None, width=3),
                   ByteEnumField("type", HTTP2FrameTypes.DATA, HTTP2_FRAME_TYPES),
                   FlagsField("flags", 0, 8, HTTP2_FLAGS.values()),
                   StrFixedLenField("stream_id", "\x00" * 32, 32)]


class HTTP2PaddedFrame(Packet):

    def pre_dissect(self, s):
        if self.underlayer is not None and has_flag_set(self.underlayer, HTTP2Flags.PADDED):
            padding_length = ord(s[0])
            self.padding = s[-padding_length:]
            s = s[:-padding_length]
        return s


def underlayer_has_flag_set(pkt, flag):
    flag_index = HTTP2_FLAGS.keys().index(flag)
    return True if pkt.underlayer is not None and (pkt.underlayer.flags & flag) >> flag_index == 1 else False

underlayer_has_padding_flag_set = lambda pkt: underlayer_has_flag_set(pkt, HTTP2Flags.PADDED)
underlayer_has_priority_flag_set = lambda pkt: underlayer_has_flag_set(pkt, HTTP2Flags.PRIORITY)


class HTTP2Data(HTTP2PaddedFrame):
    name = "%s Frame" % HTTP2_FRAME_TYPES[HTTP2FrameTypes.DATA]
    fields_desc = [ConditionalField(FieldLenField("padding_length", None, length_of="padding", fmt="B"),
                                    underlayer_has_padding_flag_set),
                   StrField("data", ":method = GET\r\n:scheme = https\r\n:path = /\r\n"),
                   ConditionalField(StrLenField("padding", "", length_from=lambda pkt: pkt.padding_length),
                                    underlayer_has_padding_flag_set)]

class HTTP2Headers(HTTP2PaddedFrame):
    name = "%s Frame" % HTTP2_FRAME_TYPES[HTTP2FrameTypes.HEADERS]
    fields_desc = [ConditionalField(FieldLenField("padding_length", None, length_of="padding", fmt="B"),
                                    underlayer_has_padding_flag_set),
                   ConditionalField(StrFixedLenField("dependency", "", 32), underlayer_has_priority_flag_set),
                   ConditionalField(ByteField("weight", 0), underlayer_has_priority_flag_set),
                   # Encoding for => Host: 127.0.0.1
                   StrField("headers", "f\x87\x08\x9d\\\x0b\x81p\xff"),
                   ConditionalField(StrLenField("padding", "", length_from=lambda pkt: pkt.padding_length),
                                    underlayer_has_padding_flag_set)]


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
        # Consume all bytes passed to us by the underlayer. We're expecting no
        # further payload on top of us. If there is additional data on top of our layer
        # We will incorrectly parse it
        while pos < len(raw_bytes) - frame_header_len:
            payload_len = frame(raw_bytes[pos: pos + frame_header_len]).length
            payload = frame(raw_bytes[pos: pos + frame_header_len + payload_len])
            # Populate our list of found frames
            frames.append(payload)
            # Move to the next record
            pos += (frame_header_len + payload.length)
        self.fields["frames"] = frames
        # This will always be empty (equivalent to returning "")
        return raw_bytes[pos:]


def generate_stream_id():
    return "%s%s" % (random.randint(0x0, 0xff) ^ (1 << 7), os.urandom(31))

def pack_headers(encoder, headers):
    return encoder.encode(headers)

def unpack_headers(decoder, str_):
    return decoder.decode(str_)

bind_layers(TCP, HTTP2Frame, dport=443)
bind_layers(TCP, HTTP2Frame, sport=443)
bind_layers(HTTP2Frame, HTTP2Data, type=HTTP2FrameTypes.DATA)
bind_layers(HTTP2Frame, HTTP2Headers, type=HTTP2FrameTypes.HEADERS)
