# -*- coding: utf-8 -*-

import unittest

import mock.mock as mock
import requests
from scapy.packet import Raw

from scapy_http2.http2 import *


class TestHTTP2Preface(unittest.TestCase):
    def test_http2_preface_is_constant(self):
        self.assertEqual(HTTP2Preface.MAGIC, str(HTTP2Preface()))

    def test_when_http2_preface_is_present_it_is_dissected(self):
        built_pkt = HTTP2Preface()/HTTP2Frame()/HTTP2Settings()
        pkt = HTTP2(str(built_pkt))
        self.assertTrue(pkt.haslayer(HTTP2Preface))
        self.assertTrue(pkt.haslayer(HTTP2Frame))
        self.assertEqual(HTTP2FrameTypes.SETTINGS, pkt[HTTP2Frame].type)

    def test_when_http2_preface_is_absent_it_is_not_dissected(self):
        built_pkt = HTTP2Frame()/HTTP2Settings()
        pkt = HTTP2(str(built_pkt))
        self.assertFalse(pkt.haslayer(HTTP2Preface))
        self.assertTrue(pkt.haslayer(HTTP2Frame))
        self.assertEqual(HTTP2FrameTypes.SETTINGS, pkt[HTTP2Frame].type)


class TestHTTP2FrameHeader(unittest.TestCase):
    def test_built_and_dissected_packet_are_identical(self):
        payload = "A" * 10
        id_ = 0xabcd
        built_pkt = HTTP2Frame(type=HTTP2FrameTypes.HEADERS, flags=HTTP2Flags.PRIORITY, stream=id_) / payload
        pkt = HTTP2Frame(str(built_pkt))
        self.assertEqual(HTTP2FrameTypes.HEADERS, pkt.type)
        self.assertEqual(HTTP2Flags.PRIORITY, pkt.flags)
        self.assertEqual(id_, pkt.stream)
        self.assertEqual(payload, str(pkt.payload))
        self.assertEqual(len(payload), pkt.length)


class TestHTTP2PaddedFrame(unittest.TestCase):
    def test_when_padding_flag_is_unset_padding_is_disabled(self):
        data = "A" * 10
        built_pkt = HTTP2Frame(flags=HTTP2Flags.ACK) / HTTP2Data(data=data)
        pkt = HTTP2Frame(str(built_pkt))
        self.assertIsNone(pkt.padding_length)
        self.assertFalse(pkt.haslayer(Padding))

    def test_when_padding_flag_is_set_padding_is_enabled(self):
        data = "A" * 10
        padding = "B" * 5
        built_pkt = HTTP2Frame(flags=HTTP2Flags.PADDED) / HTTP2Data(data=data) / Padding(load=padding)
        pkt = HTTP2Frame(str(built_pkt))
        self.assertTrue(pkt.haslayer(HTTP2Data))
        self.assertEqual(len(padding), pkt[HTTP2Data].padding_length)
        self.assertEqual(padding, pkt[Padding].load)


class TestHTTP2Headers(unittest.TestCase):
    def test_when_priority_flag_is_set_stream_dependency_and_weight_are_enabled(self):
        stream_dependency = 0x9876
        weight = 0xff
        built_pkt = HTTP2Frame(flags=HTTP2Flags.PRIORITY) / HTTP2Headers(stream_dependency=stream_dependency,
                                                                         weight=weight)
        pkt = HTTP2Frame(str(built_pkt))
        self.assertTrue(pkt.haslayer(HTTP2Headers))
        self.assertEqual(stream_dependency, pkt[HTTP2Headers].stream_dependency)
        self.assertEqual(weight, pkt[HTTP2Headers].weight)

    def test_when_priority_flag_is_unset_stream_dependency_and_weight_are_disabled(self):
        headers = "X-Some-Header: some-value"
        built_pkt = HTTP2Frame(flags=HTTP2Flags.UNUSED_2) / HTTP2Headers(headers=headers)
        pkt = HTTP2Frame(str(built_pkt))
        self.assertTrue(pkt.haslayer(HTTP2Headers))
        self.assertIsNone(pkt[HTTP2Headers].stream_dependency)
        self.assertIsNone(pkt[HTTP2Headers].weight)

    def test_when_both_priority_and_padded_flag_are_set_all_options_are_enabled(self):
        stream_dependency = 0x1234
        weight = 0xff
        padding = "P" * 23
        built_pkt = HTTP2Frame(flags=HTTP2Flags.PADDED | HTTP2Flags.PRIORITY) / HTTP2Headers(
            stream_dependency=stream_dependency, weight=weight) / Padding(load=padding)
        pkt = HTTP2Frame(str(built_pkt))
        self.assertTrue(pkt.haslayer(HTTP2Headers))
        self.assertEqual(stream_dependency, pkt[HTTP2Headers].stream_dependency)
        self.assertEqual(weight, pkt[HTTP2Headers].weight)
        self.assertEqual(padding, pkt[Padding].load)

    def test_when_both_priority_and_padded_flag_are_unset_all_options_are_disabled(self):
        headers = "X-Some-Header: some-value"
        built_pkt = HTTP2Frame(flags=HTTP2Flags.END_HEADERS) / HTTP2Headers(headers=headers)
        pkt = HTTP2Frame(str(built_pkt))
        self.assertTrue(pkt.haslayer(HTTP2Headers))
        self.assertIsNone(pkt[HTTP2Headers].padding_length)
        self.assertIsNone(pkt[HTTP2Headers].stream_dependency)
        self.assertIsNone(pkt[HTTP2Headers].weight)
        self.assertFalse(pkt.haslayer(Padding))


class TestHTTP2Settings(unittest.TestCase):
    def test_frame_containing_multiple_settings_is_correctly_dissected(self):
        setting1 = HTTP2Setting(id=HTTP2SettingIds.SETTINGS_MAX_HEADER_LIST_SIZE, value=128)
        setting2 = HTTP2Setting(id=HTTP2SettingIds.SETTINGS_MAX_CONCURRENT_STREAMS, value=100)
        frame1 = HTTP2Frame() / HTTP2Settings(settings=[setting1, setting2]) / ("A" * 5)
        frame2 = HTTP2Frame() / HTTP2RstStream(error_code="SETTINGS_TIMEOUT")
        built_pkt = HTTP2.from_frames((frame1, frame2))
        pkt = HTTP2(str(built_pkt))
        self.assertTrue(pkt.frames[0].haslayer(HTTP2Settings))
        self.assertEqual(2, len(pkt.frames[0][HTTP2Settings].settings))
        self.assertEqual(setting1, pkt.frames[0][HTTP2Settings].settings[0])
        self.assertEqual(setting2, pkt.frames[0][HTTP2Settings].settings[1])
        self.assertEqual("A" * 5, str(pkt.frames[0][Raw]))
        self.assertTrue(pkt.frames[1].haslayer(HTTP2RstStream))
        self.assertEqual(str(frame2), str(pkt.frames[1]))


class TestHTTP2(unittest.TestCase):
    def test_stacked_frame_packet_are_dissected_correctly(self):
        frame1 = HTTP2Frame(stream=0x5, flags=HTTP2Flags.UNUSED_7) / HTTP2Headers()
        frame2 = HTTP2Frame(flags=HTTP2Flags.PADDED | HTTP2Flags.PRIORITY) / HTTP2Data() / Padding(load="P" * 23)
        frame3 = HTTP2Frame() / HTTP2Priority(stream_dependency=0x5, weight=5)
        frame4 = HTTP2Frame() / HTTP2RstStream(error_code=HTTP2ErrorCodes.REFUSED_STREAM)
        frame5 = HTTP2Frame(flags=HTTP2Flags.PADDED) / HTTP2PushPromise(promised_stream=0xffe34) / Padding(load="Z" * 9)
        frame6 = HTTP2Frame(flags=HTTP2Flags.UNUSED_2 | HTTP2Flags.ACK) / HTTP2Ping()
        frame7 = HTTP2Frame() / HTTP2GoAway(last_stream=0x567, error_code=HTTP2ErrorCodes.COMPRESSION_ERROR,
                                            debug_data="jkl" * 43)
        frame8 = HTTP2Frame() / HTTP2WindowUpdate(window_size=2 ** 31 - 1) / "Trailing Data"
        frame9 = HTTP2Frame(flags=HTTP2Flags.PADDED) / HTTP2Continuation(headers="some-headers")
        built_pkt = HTTP2.from_frames([frame1, frame2, frame3, frame4, frame5, frame6, frame7, frame8, frame9])
        pkt = HTTP2(str(built_pkt))
        self.assertTrue(len(pkt.frames) == 9)
        self.assertEqual(str(frame1), str(pkt.frames[0]))
        self.assertEqual(str(frame2), str(pkt.frames[1]))
        self.assertEqual(str(frame3), str(pkt.frames[2]))
        self.assertEqual(str(frame4), str(pkt.frames[3]))
        self.assertEqual(str(frame5), str(pkt.frames[4]))
        self.assertTrue(pkt.frames[4].haslayer(Padding))
        self.assertEqual(str(frame6), str(pkt.frames[5]))
        self.assertEqual(str(frame7), str(pkt.frames[6]))
        self.assertEqual(str(frame8), str(pkt.frames[7]))
        self.assertTrue(pkt.frames[7].haslayer(Raw))
        self.assertEqual(str(frame9), str(pkt.frames[8]))


class TestHTTP2Socket(unittest.TestCase):
    def setUp(self):
        self.frame_sut = HTTP2Frame()
        self.socket_mock = mock.Mock()
        self.socket_mock.sendall = mock.MagicMock(name="socket_sendall")
        self.socket_mock.recv = mock.MagicMock(name="socket_recv", side_effect=[str(self.frame_sut),
                                                                                socket.timeout("Mocked timeout")])
        self.http2_socket = HTTP2Socket(self.socket_mock)
        super(TestHTTP2Socket, self).setUp()

    def _mock_http2_network_calls(self):
        self.http2_socket.sendall = mock.MagicMock(name="http2_socket_sendall")
        self.http2_socket.recvall = mock.MagicMock(name="http2_socket_recvall", side_effect=self.frame_sut)

    def test_when_sendall_is_called_data_is_sent_on_socket(self):
        frame_sut = HTTP2Frame()
        self.http2_socket.sendall(frame_sut)
        self.socket_mock.sendall.assert_called_once_with(str(frame_sut))

    def test_when_data_is_received_on_socket_recvall_retrieves_it(self):
        pkt = self.http2_socket.recvall()
        self.assertEqual(2, self.socket_mock.recv.call_count)
        self.assertEqual(str(self.frame_sut), str(pkt))

    def test_when_upgrade_headers_are_missing_they_are_added(self):
        self._mock_http2_network_calls()
        req = requests.Request("GET", "http://1.2.3.4:1234/a/b/c/d?1=2&3=4")
        prep_req = req.prepare()
        self.http2_socket.send_upgrade(prep_req)
        arg = self.http2_socket.sendall.call_args[0][0]
        self.assertTrue("Upgrade" in arg)
        self.assertTrue("Connection" in arg)
        self.assertTrue("HTTP2-Settings" in arg)

    def test_when_upgrade_header_is_present_it_is_preserved(self):
        self._mock_http2_network_calls()
        req = requests.Request("POST", "http://1.2.3.4:1234/a/b/c/d", headers={"conNecTion": "abcdefg"},
                               data={"a": "b", "1": "2"})
        prep_req = req.prepare()
        self.http2_socket.send_upgrade(prep_req)
        arg = self.http2_socket.sendall.call_args[0][0]
        self.assertTrue("conNecTion: abcdefg" in arg)
        self.assertFalse("Upgrade, HTTP2-Settings" in arg)


class TestTopLevelFunctions(unittest.TestCase):
    def test_when_flags_are_set_they_are_caught(self):
        pkt = HTTP2Frame(flags=HTTP2Flags.PRIORITY)
        self.assertTrue(has_flag_set(pkt, HTTP2Flags.PRIORITY))
        self.assertFalse(has_flag_set(pkt, HTTP2Flags.UNUSED_5))
        pkt = HTTP2Frame(flags=HTTP2Flags.ACK | HTTP2Flags.END_HEADERS | HTTP2Flags.UNUSED_8)
        self.assertTrue(has_flag_set(pkt, HTTP2Flags.ACK))
        self.assertTrue(has_flag_set(pkt, HTTP2Flags.END_HEADERS))
        self.assertTrue(has_flag_set(pkt, HTTP2Flags.UNUSED_8))
        self.assertFalse(has_flag_set(pkt, HTTP2Flags.UNUSED_2))
        self.assertFalse(has_flag_set(pkt, HTTP2Flags.PRIORITY))
        self.assertFalse(has_flag_set(pkt, HTTP2Flags.UNUSED_7))

    def test_stream_ids_are_generated_in_steps_of_2(self):
        self.assertListEqual([4, 6, 8], list(get_stream_ids(4, 9)))

    def test_generated_client_side_ids_are_odd(self):
        with self.assertRaises(ValueError):
            list(get_client_stream_ids(4, 9))
        self.assertListEqual([5, 7], list(get_client_stream_ids(5, 9)))

    def test_generated_server_side_ids_are_even(self):
        with self.assertRaises(ValueError):
            list(get_server_stream_ids(5, 9))
        self.assertListEqual([4, 6, 8], list(get_server_stream_ids(4, 9)))
