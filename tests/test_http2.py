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

    def test_when_padding_flag_is_unset_padding_is_disabled(self):
        data = "A" * 10
        built_pkt = HTTP2Frame(flags=HTTP2Flags.END_STREAM)/HTTP2Data(data=data)
        pkt = HTTP2Frame(str(built_pkt))
        self.assertIsNone(pkt.padding_length)
        self.assertEqual("", pkt.padding)

    def test_when_padding_flag_is_set_padding_is_enabled(self):
        data = "A" * 10
        padding = "B" * 5
        built_pkt = HTTP2Frame(flags=HTTP2Flags.PADDED)/HTTP2Data(data=data, padding=padding)
        pkt = HTTP2Frame(str(built_pkt))
        self.assertTrue(pkt.haslayer(HTTP2Data))
        self.assertEqual(len(padding), pkt[HTTP2Data].padding_length)
        self.assertEqual(padding, pkt[HTTP2Data].padding)


class TestHTTP2Headers(unittest.TestCase):

    def test_when_priority_flag_is_set_stream_dependency_and_weight_are_enabled(self):
        stream_dependency = "D" * 32
        weight = 0xff
        built_pkt = HTTP2Frame(flags=HTTP2Flags.PRIORITY)/HTTP2Headers(dependency=stream_dependency, weight=weight)
        pkt = HTTP2Frame(str(built_pkt))
        self.assertTrue(pkt.haslayer(HTTP2Headers))
        self.assertEqual(stream_dependency, pkt[HTTP2Headers].dependency)
        self.assertEqual(weight, pkt[HTTP2Headers].weight)

    def test_when_priority_flag_is_unset_stream_dependency_and_weight_are_disabled(self):
        headers = "X-Some-Header: some-value"
        built_pkt = HTTP2Frame(flags=HTTP2Flags.UNUSED_2)/HTTP2Headers(headers=headers)
        pkt = HTTP2Frame(str(built_pkt))
        self.assertTrue(pkt.haslayer(HTTP2Headers))
        self.assertIsNone(pkt[HTTP2Headers].dependency)
        self.assertIsNone(pkt[HTTP2Headers].weight)

    def test_when_both_priority_and_padded_flag_are_set_all_options_are_enabled(self):
        stream_dependency = "D" * 32
        weight = 0xff
        padding = "P" * 23
        built_pkt = HTTP2Frame(flags=HTTP2Flags.PADDED | HTTP2Flags.PRIORITY)/HTTP2Headers(dependency=stream_dependency, weight=weight, padding=padding)
        pkt = HTTP2Frame(str(built_pkt))
        self.assertTrue(pkt.haslayer(HTTP2Headers))
        self.assertEqual(stream_dependency, pkt[HTTP2Headers].dependency)
        self.assertEqual(weight, pkt[HTTP2Headers].weight)
        self.assertEqual(padding, pkt[HTTP2Headers].padding)

    def test_when_both_priority_and_padded_flag_are_unset_all_options_are_disabled(self):
        headers = "X-Some-Header: some-value"
        built_pkt = HTTP2Frame(flags=HTTP2Flags.END_HEADERS)/HTTP2Headers(headers=headers)
        pkt = HTTP2Frame(str(built_pkt))
        self.assertTrue(pkt.haslayer(HTTP2Headers))
        self.assertIsNone(pkt[HTTP2Headers].padding_length)
        self.assertIsNone(pkt[HTTP2Headers].dependency)
        self.assertIsNone(pkt[HTTP2Headers].weight)
        self.assertEqual("", pkt[HTTP2Headers].padding)


class TestHTTP2(unittest.TestCase):

    def test_stacked_frame_packet_are_dissected_correctly(self):
        frame1 = HTTP2Frame(stream_id="B" * 32, flags=HTTP2Flags.UNUSED_7)/HTTP2Headers()
        frame2 = HTTP2Frame(flags=HTTP2Flags.PADDED | HTTP2Flags.PRIORITY, type=0xff)/HTTP2Data(padding="P" * 23)
        frame3 = HTTP2Frame()/HTTP2Priority(dependency="D" * 32, weight=5)
        built_pkt = HTTP2.from_frames([frame1, frame2, frame3])
        pkt = HTTP2(str(built_pkt))
        pkt.show()
        self.assertTrue(len(pkt.frames) == 3)
        self.assertEqual(str(frame1), str(pkt.frames[0]))
        self.assertEqual(str(frame2), str(pkt.frames[1]))
        self.assertEqual(str(frame3), str(pkt.frames[2]))


class TestTopLevelFunctions(unittest.TestCase):

    def test_stream_id_first_bit_is_clear(self):
        for i in range(0, 0xff):
            self.assertTrue(ord(generate_stream_id()[0]) & (1 << 7) == 0)

    def test_when_flags_are_set_they_are_caught(self):
        pkt = HTTP2Frame(flags=HTTP2Flags.PRIORITY)
        self.assertTrue(has_flag_set(pkt, HTTP2Flags.PRIORITY))
        self.assertFalse(has_flag_set(pkt, HTTP2Flags.UNUSED_5))
        pkt = HTTP2Frame(flags=HTTP2Flags.END_STREAM | HTTP2Flags.END_HEADERS | HTTP2Flags.UNUSED_8)
        self.assertTrue(has_flag_set(pkt, HTTP2Flags.END_STREAM))
        self.assertTrue(has_flag_set(pkt, HTTP2Flags.END_HEADERS))
        self.assertTrue(has_flag_set(pkt, HTTP2Flags.UNUSED_8))
        self.assertFalse(has_flag_set(pkt, HTTP2Flags.UNUSED_2))
        self.assertFalse(has_flag_set(pkt, HTTP2Flags.PRIORITY))
        self.assertFalse(has_flag_set(pkt, HTTP2Flags.UNUSED_7))

    def test_when_e_flag_is_set_first_bit_is_set(self):
        stream_dependency_id = set_dependency_e_flag("%s%s" % (chr(0x7f), "S" * 31))
        self.assertEqual(0x7f | 0x80, ord(stream_dependency_id[0]))
