use super::*;

#[test]
fn go_wire_fields_keep_order_nulls_binary_and_integer_ranges() {
    let message=Message::decode(br#"{"TYPE":"request","type":null,"BODY":[0,127,255,null],"Status_Code":-1,"LOCAL_PORT":-42,"stream_id":18446744073709551615,"header":{"X-Greendale":[null,"Troy"]}}"#).unwrap();
    assert_eq!(message.kind, "request");
    assert_eq!(message.body, [0, 127, 255, 0]);
    assert_eq!(message.status_code, -1);
    assert_eq!(message.local_port, -42);
    assert_eq!(message.stream_id, u64::MAX);
    assert_eq!(message.header["X-Greendale"], ["", "Troy"]);
    assert_eq!(
        Message::decode(br#"{"type":"request","TYPE":"response","body":"Zh=="}"#)
            .unwrap()
            .kind,
        "response"
    );
    assert_eq!(Message::decode(br#"{"body":"Zh=="}"#).unwrap().body, b"f");
    for invalid in [
        br#"{"body":[256]}"#.as_slice(),
        br#"{"status_code":9223372036854775808}"#,
        br#"{"body":"!"}"#,
    ] {
        assert!(Message::decode(invalid).is_err());
    }
}

#[test]
fn message_limits_allow_base64_and_metadata_without_integer_overflow() {
    assert_eq!(max_message_bytes(-1), 1 << 20);
    assert_eq!(max_message_bytes(0), 1 << 20);
    assert_eq!(max_message_bytes(1), (1 << 20) + 4);
    assert_eq!(max_message_bytes(3), (1 << 20) + 4);
    assert_eq!(max_message_bytes(4), (1 << 20) + 8);
    assert_eq!(max_message_bytes(MAX_BODY as i64), MAX_MESSAGE as i64);
    assert_eq!(max_message_bytes(i64::MAX), i64::MAX);
}
