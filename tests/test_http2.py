# -*- coding: utf-8 -*-

import unittest

from http2 import *


class TestHTTP2FrameHeader(unittest.TestCase):

    def test_built_and_dissected_packet_are_identical(self):
        payload = "A" * 10
        id_ = os.urandom(32)
        built_pkt = HTTP2Frame(type=HTTP2FrameTypes.HEADERS, flags=HTTP2Flags.PRIORITY, stream_id=id_)/payload
        pkt = HTTP2Frame(str(built_pkt))
        self.assertEqual(HTTP2FrameTypes.HEADERS, pkt.type)
        self.assertEqual(HTTP2Flags.PRIORITY, pkt.flags)
        self.assertEqual(id_, pkt.stream_id)
        self.assertEqual(payload, str(pkt.payload))
        self.assertEqual(len(payload), pkt.length)


class TestHTTP2PaddedFrame(unittest.TestCase):

    def test_when_padding_flag_is_not_set_no_padding_is_added(self):
        data = "A" * 10
        built_pkt = HTTP2Frame(flags=HTTP2Flags.END_STREAM)/HTTP2Data(data=data)
        self.assertIsNone(built_pkt.padding_length)
        self.assertEqual("", built_pkt.padding)

    def test_when_padding_flag_is_set_padding_is_added(self):
        data = "A" * 10
        padding = "B" * 5
        built_pkt = HTTP2Frame(flags=HTTP2Flags.PADDED)/HTTP2Data(data=data, padding=padding)
        pkt = HTTP2Frame(str(built_pkt))
        self.assertTrue(pkt.haslayer(HTTP2Data))
        self.assertEqual(len(padding), pkt[HTTP2Data].padding_length)
        self.assertEqual(padding, pkt[HTTP2Data].padding)


class TestHTTP2Headers(unittest.TestCase):

    def test_bitch(self):
        pass
        # built_pkt = HTTP2Frame(stream_id="\xff"*32)/HTTP2Headers(headers="123")
        # pkt = HTTP2Frame(str(built_pkt))


class TestHTTP2(unittest.TestCase):

    def test_stacked_frame_packet_are_dissected_correctly(self):
        frame1 = HTTP2Frame()/HTTP2Headers()
        frame2 = HTTP2Frame()/HTTP2Data()
        built_pkt = HTTP2.from_frames([frame1, frame2])
        pkt = HTTP2(str(built_pkt))
        self.assertTrue(len(pkt.frames) == 2)
        self.assertEqual(str(frame1), str(pkt.frames[0]))
        self.assertEqual(str(frame2), str(pkt.frames[1]))


class TestTopLevelFunctions(unittest.TestCase):

    def test_stream_id_first_bit_is_clear(self):
        pkt = HTTP2Frame()
        self.assertTrue(ord(pkt.stream_id[0]) & (1 << 7) == 0)
