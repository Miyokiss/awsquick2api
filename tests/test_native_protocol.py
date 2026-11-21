import base64
import json
import struct
import uuid
import zlib

import cbor2
import pytest

from quickpool.native_protocol import (
    DESKTOP_SURFACE,
    EventStreamDecoder,
    EventStreamFrame,
    NativeMessageDecoder,
    NativeProtocolError,
    NativeTextEvents,
    build_conversation_connect,
    build_session_connect,
    build_session_create,
    build_token_refresh,
    build_user_message,
    decode_frame,
    encode_aidp_message,
    encode_eventstream,
    encode_gateway_message,
    encode_message,
)


def output(transport, event):
    raw = json.dumps(event, ensure_ascii=False).encode()
    body = cbor2.dumps({"payload": raw}) if transport == "gateway" else json.dumps(
        {"payload": base64.b64encode(raw).decode()}).encode()
    return encode_eventstream({":message-type": "event", ":event-type": "rawOutputEvent"}, body)


def with_raw_headers(headers):
    prelude = struct.pack(">II", 16 + len(headers), len(headers))
    frame = prelude + struct.pack(">I", zlib.crc32(prelude)) + headers
    return frame + struct.pack(">I", zlib.crc32(frame))


def test_gateway_outgoing_exact_wrapper_and_crc():
    event = {"type": "user_message", "payload": {"text": "你好"}}
    raw = encode_gateway_message(event)
    decoder = EventStreamDecoder()
    frame, = decoder.feed(raw)
    decoder.finish()
    assert frame.headers == {":event-type": "rawInputEvent", ":content-type": "application/cbor",
                             ":message-type": "event"}
    assert cbor2.loads(frame.payload) == {"payload": b'{"type":"user_message","payload":{"text":"\xe4\xbd\xa0\xe5\xa5\xbd"}}'}
    assert struct.unpack(">I", raw[8:12])[0] == zlib.crc32(raw[:8])
    assert struct.unpack(">I", raw[-4:])[0] == zlib.crc32(raw[:-4])


def test_gateway_matches_official_124660_encoder_golden_vector():
    # Captured offline from Quick 1.2.4660 gatewayBidiCodec.buildGatewayInputFrame.
    golden = bytes.fromhex(
        "0000009700000053f46624270b3a6576656e742d7479706507000d726177496e7075744576656e74"
        "0d3a636f6e74656e742d747970650700106170706c69636174696f6e2f63626f72"
        "0d3a6d6573736167652d747970650700056576656e74a1677061796c6f61645829"
        "7b2274797065223a2270696e67222c227061796c6f6164223a7b2274696d657374616d70223a317d7dafe94136")
    assert encode_gateway_message({"type": "ping", "payload": {"timestamp": 1}}) == golden


def test_aidp_outgoing_is_json_binary_not_gateway_framing():
    event = {"type": "ping", "payload": {"timestamp": 1}}
    raw = encode_aidp_message(event)
    envelope = json.loads(raw)
    assert envelope["eventType"] == "rawInputEvent"
    assert json.loads(base64.b64decode(envelope["payload"]["payload"], validate=True)) == event
    assert raw.startswith(b'{')
    assert encode_message("aidp", event) == raw
    assert encode_message("gateway", event) == encode_gateway_message(event)


@pytest.mark.parametrize("transport", ["gateway", "aidp"])
def test_incremental_frames_and_multiple_frames(transport):
    events = [{"type": "text_delta", "payload": {"delta": "你好"}}, {"type": "message_complete"}]
    raw = b''.join(output(transport, event) for event in events)
    decoder = NativeMessageDecoder(transport)
    result = []
    for byte in raw:
        result.extend(decoder.feed(bytes([byte])))
    decoder.finish()
    assert result == events
    assert decoder.eventstream.buffered_bytes == 0
    assert NativeMessageDecoder(transport).feed(raw) == events


@pytest.mark.parametrize("offset", [0, 4, 8, 15, -1])
def test_corrupt_frame_fails_closed(offset):
    raw = bytearray(output("gateway", {"type": "connected"}))
    raw[offset] ^= 1
    decoder = EventStreamDecoder()
    with pytest.raises(NativeProtocolError):
        decoder.feed(raw)
    assert decoder.buffered_bytes == 0
    with pytest.raises(NativeProtocolError, match="failed"):
        decoder.feed(output("gateway", {}))


@pytest.mark.parametrize("length", [0, 1, 15, 17 * 1024 * 1024])
def test_bad_lengths_rejected_before_waiting_for_body(length):
    prelude = struct.pack(">II", length, 0)
    with pytest.raises(NativeProtocolError, match="length"):
        EventStreamDecoder().feed(prelude + struct.pack(">I", zlib.crc32(prelude)))


def test_headers_larger_than_frame_and_custom_limit():
    prelude = struct.pack(">II", 16, 1)
    with pytest.raises(NativeProtocolError):
        EventStreamDecoder().feed(prelude + struct.pack(">I", zlib.crc32(prelude)))
    with pytest.raises(NativeProtocolError):
        EventStreamDecoder(16).feed(output("gateway", {}))


@pytest.mark.parametrize("cut", [1, 8, 11, 12, 17, -1])
def test_truncated_frames(cut):
    decoder = EventStreamDecoder()
    assert decoder.feed(output("aidp", {"type": "x"})[:cut]) == []
    with pytest.raises(NativeProtocolError, match="Truncated"):
        decoder.finish()


def test_all_header_types():
    values = [b'\x00', b'\x01', b'\x02\xff', b'\x03\xff\xfe',
              b'\x04' + struct.pack('>i', -3), b'\x05' + struct.pack('>q', -4),
              b'\x06\x00\x02ab', b'\x07\x00\x02hi',
              b'\x08' + struct.pack('>q', 10), b'\x09' + bytes(range(16))]
    raw = b''.join(bytes([1]) + str(i).encode() + value for i, value in enumerate(values))
    frame, = EventStreamDecoder().feed(with_raw_headers(raw))
    assert list(frame.headers.values()) == [True, False, -1, -2, -3, -4, b'ab', 'hi', 10,
                                           uuid.UUID(bytes=bytes(range(16)))]


@pytest.mark.parametrize("raw", [b'\x00', b'\x01a', b'\x01a\xff', b'\x01a\x07\x00\x03x',
                                  b'\x01a\x00\x01a\x01', b'\x01\xff\x00'])
def test_malformed_headers(raw):
    with pytest.raises(NativeProtocolError):
        EventStreamDecoder().feed(with_raw_headers(raw))


@pytest.mark.parametrize("transport", ["gateway", "aidp"])
def test_protocol_errors_never_echo_upstream_data(transport):
    secret = "SENSITIVE_BEARER_CANARY"
    raw = encode_eventstream({":message-type": "exception", ":exception-type": secret,
                              ":error-message": secret}, secret.encode())
    with pytest.raises(NativeProtocolError) as error:
        NativeMessageDecoder(transport).feed(raw)
    assert secret not in str(error.value)
    assert secret not in repr(error.value)
    frame = EventStreamFrame({":event-type": "rawOutputEvent"}, secret.encode())
    with pytest.raises(NativeProtocolError) as error:
        decode_frame(transport, frame)
    assert secret not in str(error.value)


def test_gateway_cbor_indefinite_and_trailing_rejection():
    # Indefinite map and byte-string chunks are accepted by the desktop decoder.
    raw = b'\xbf\x67payload\x5f\x42{}\x40\xff\xff'
    assert decode_frame("gateway", EventStreamFrame({}, raw)) == {}
    with pytest.raises(NativeProtocolError):
        decode_frame("gateway", EventStreamFrame({}, cbor2.dumps({"payload": b'{}'}) + b'\x00'))
    assert decode_frame("gateway", EventStreamFrame({}, cbor2.dumps({"payload": '{}'}))) == {}


@pytest.mark.parametrize("payload", [b'{}', b'{"payload":"bad!"}', b'{"payload":1}',
                                      b'{"payload":"W10="}'])
def test_bad_aidp_payloads(payload):
    with pytest.raises(NativeProtocolError):
        decode_frame("aidp", EventStreamFrame({":event-type": "rawOutputEvent"}, payload))


def test_empty_and_nonoutput_aidp_frames_are_ignored():
    assert decode_frame("gateway", EventStreamFrame({}, b'')) is None
    assert decode_frame("aidp", EventStreamFrame({":event-type": "keepalive"}, b'ignored')) is None


def test_invalid_outbound_and_transport_errors_are_safe():
    for message in ['SENSITIVE_BEARER_CANARY', '[]', {"x": float('nan')}]:
        with pytest.raises(NativeProtocolError) as error:
            encode_aidp_message(message)
        assert 'SENSITIVE_BEARER_CANARY' not in str(error.value)
    with pytest.raises(NativeProtocolError):
        NativeMessageDecoder("unknown")
    with pytest.raises(NativeProtocolError):
        encode_eventstream({"a": "b" * 65536}, b'')


def test_native_helpers():
    assert build_session_connect("gateway", outpost_id="device") == {
        "type": "session_connect", "session_id": "device"}
    aidp = build_session_connect("aidp", outpost_id="device", actor_arn="actor", app_version="1.2.4660")
    assert aidp["payload"]["actor_id"] == "actor"
    assert aidp["payload"]["surfaceType"] == DESKTOP_SURFACE
    assert aidp["payload"]["outpostId"] == "device"
    assert aidp["payload"]["appVersion"] == "1.2.4660"
    conversation = build_conversation_connect("thread", last_event_id="event")
    assert conversation["payload"]["session_id"] == "thread"
    assert conversation["payload"]["last_event_id"] == "event"
    assert conversation["payload"]["focus_only"] is True
    assert build_session_create("thread")["payload"]["title"] == "New Conversation"
    payload = build_user_message("你好", "thread", message_id="msg", trace_id="trace")["payload"]
    assert payload["text"] == "你好" and payload["thread_id"] == "thread"
    assert payload["message_id"] == "msg" and payload["traceId"] == "trace"
    assert payload["voice_mode"] is False and payload["custom_prompt"] is None
    assert json.loads(build_token_refresh("fresh")) == {"type": "token_refresh", "token": "fresh"}


def event(kind, payload=None, thread="thread", message="m1", event_id=None):
    result = {"type": kind, "thread_id": thread, "message_id": message, "payload": payload or {}}
    if event_id is not None:
        result["event_id"] = event_id
    return result


def test_text_continuation_snapshots_and_thread_filter():
    text = NativeTextEvents("thread")
    assert text.feed(event("text_delta", {"delta": "ignored"}, thread="other")).delta == ""
    text.feed(event("message_start"))
    assert text.feed(event("text_delta", {"delta": "你好"})).delta == "你好"
    assert text.feed(event("text_complete", {"text": "你好"})).delta == ""
    assert not text.feed(event("message_complete", {"continuation_expected": True})).done
    text.feed(event("message_start", message="m2"))
    assert text.feed(event("text_delta", {"delta": "，世"}, message="m2")).delta == "，世"
    assert text.feed(event("stream_snapshot", {"text": "，世界"}, message="m2")).delta == "界"
    assert text.feed(event("text_complete", {"text": "，世"}, message="m2")).delta == ""
    assert text.feed(event("message_complete", message="m1")).done is False
    assert text.feed(event("message_complete", message="m2")).done is True
    assert text.text == "你好，世界"
    assert text.feed(event("text_delta", {"delta": "late"}, message="m2")).delta == ""


def test_replayed_event_ids_do_not_duplicate_deltas():
    text = NativeTextEvents("thread")
    item = event("text_delta", {"delta": "hello"}, event_id="e1")
    assert text.feed(item).delta == "hello"
    assert text.feed(item).delta == ""
    assert text.text == "hello"


def test_replayed_earlier_message_start_cannot_steal_current_bubble():
    text = NativeTextEvents("thread")
    text.feed(event("message_start"))
    text.feed(event("text_delta", {"delta": "one"}))
    text.feed(event("message_complete", {"continuation_expected": True}))
    text.feed(event("message_start", message="m2"))
    text.feed(event("message_start"))
    assert text.feed(event("text_delta", {"delta": "duplicate"})).delta == ""
    assert text.feed(event("text_delta", {"delta": "two"}, message="m2")).delta == "two"
    assert text.text == "onetwo"


def test_conflicting_snapshot_limits_and_errors_are_safe():
    text = NativeTextEvents("thread", max_text_chars=6)
    text.feed(event("text_delta", {"delta": "hello"}))
    for kind, payload in [("text_complete", {"text": "TOKEN_CANARY"}),
                          ("text_delta", {"delta": "world"}), ("error", {"message": "TOKEN_CANARY"})]:
        with pytest.raises(NativeProtocolError) as error:
            text.feed(event(kind, payload))
        assert "TOKEN_CANARY" not in str(error.value)
    assert text.text == "hello"
