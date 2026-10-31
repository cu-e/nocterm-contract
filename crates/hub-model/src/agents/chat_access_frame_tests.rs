use super::*;

const CHAT: [u8; CHAT_ID_BYTES] = [7; CHAT_ID_BYTES];

fn token() -> ChatAccessToken {
    ChatAccessToken::new(format!("nvt1_{}", "Ab-_9".repeat(12))).unwrap()
}

fn issue() -> ChatAccessFrame {
    ChatAccessFrame::Issue {
        chat: CHAT,
        token: token(),
    }
}

/// Feeds `bytes` in chunks of `chunk` and collects every frame.
fn read_all(bytes: &[u8], chunk: usize) -> Result<Vec<ChatAccessFrame>, ChatAccessFrameError> {
    let mut decoder = ChatAccessDecoder::new();
    let mut frames = Vec::new();
    for piece in bytes.chunks(chunk) {
        let mut rest = piece;
        while !rest.is_empty() {
            let (frame, next) = decoder.feed(rest)?;
            frames.extend(frame);
            rest = next;
        }
    }
    decoder.finish()?;
    Ok(frames)
}

#[test]
fn issue_and_revoke_frames_round_trip_in_any_chunking() {
    let revoke = ChatAccessFrame::Revoke { chat: [9; 16] };
    let mut stream = issue().encode().to_vec();
    stream.extend_from_slice(&revoke.encode());
    for chunk in [1, 3, 22, stream.len()] {
        let frames = read_all(&stream, chunk).unwrap();
        assert_eq!(
            frames,
            vec![issue(), ChatAccessFrame::Revoke { chat: [9; 16] }]
        );
    }
    assert_eq!(ChatAccessFrame::decode(&issue().encode()), Ok(issue()));
    assert_eq!(issue().op(), ChatAccessOp::Issue);
    assert_eq!(revoke.op(), ChatAccessOp::Revoke);
    assert_eq!(revoke.chat(), [9; 16]);
}

#[test]
fn the_layout_is_length_version_op_chat_and_token() {
    let revoke = ChatAccessFrame::Revoke { chat: CHAT }.encode();
    let mut expected = vec![0, 0, 0, 18, 1, 2];
    expected.extend_from_slice(&CHAT);
    assert_eq!(revoke.as_slice(), expected.as_slice());

    let bytes = issue().encode();
    assert_eq!(&bytes[4..6], &[1, 1]);
    assert_eq!(&bytes[22..24], &65u16.to_be_bytes());
    assert_eq!(&bytes[24..29], b"nvt1_");
    assert_eq!(bytes.len(), 4 + 18 + 2 + 65);
}

#[test]
fn an_oversized_length_is_refused_before_its_body_arrives() {
    let mut decoder = ChatAccessDecoder::new();
    let announced = u32::try_from(MAX_CHAT_ACCESS_FRAME_BYTES).unwrap();
    assert_eq!(
        decoder.feed(&announced.to_be_bytes()).map(|(f, _)| f),
        Err(ChatAccessFrameError::TooLarge(
            MAX_CHAT_ACCESS_FRAME_BYTES + 4
        ))
    );
    assert_eq!(
        decoder.feed(&[0]).map(|(f, _)| f),
        Err(ChatAccessFrameError::Failed)
    );
    assert_eq!(decoder.finish(), Err(ChatAccessFrameError::Failed));
}

#[test]
fn unknown_versions_and_operations_are_refused() {
    let mut frame = ChatAccessFrame::Revoke { chat: CHAT }.encode().to_vec();
    frame[4] = 2;
    assert_eq!(
        ChatAccessFrame::decode(&frame),
        Err(ChatAccessFrameError::UnknownVersion(2))
    );
    frame[4] = 1;
    frame[5] = 3;
    assert_eq!(
        ChatAccessFrame::decode(&frame),
        Err(ChatAccessFrameError::UnknownOp(3))
    );
    frame[5] = 0;
    assert_eq!(
        ChatAccessFrame::decode(&frame),
        Err(ChatAccessFrameError::UnknownOp(0))
    );
}

#[test]
fn truncated_input_is_reported_at_the_end_of_the_channel() {
    let bytes = issue().encode();
    for cut in [1, 4, 10, bytes.len() - 1] {
        assert_eq!(
            read_all(&bytes[..cut], 7).unwrap_err(),
            ChatAccessFrameError::Truncated,
            "cut at {cut}"
        );
        assert_eq!(
            ChatAccessFrame::decode(&bytes[..cut]),
            Err(ChatAccessFrameError::Truncated)
        );
    }
    // A body shorter than version, op and chat id.
    assert_eq!(
        ChatAccessFrame::decode(&[0, 0, 0, 2, 1, 2]),
        Err(ChatAccessFrameError::Truncated)
    );
    // An issue whose token length runs past the body.
    let mut short = issue().encode().to_vec();
    short.truncate(30);
    short[..4].copy_from_slice(&26u32.to_be_bytes());
    assert_eq!(
        ChatAccessFrame::decode(&short),
        Err(ChatAccessFrameError::Truncated)
    );
}

#[test]
fn a_revoke_carries_no_token_and_tokens_must_be_virtual_tokens() {
    let mut revoke = ChatAccessFrame::Revoke { chat: CHAT }.encode().to_vec();
    revoke[..4].copy_from_slice(&19u32.to_be_bytes());
    revoke.push(0);
    assert_eq!(
        ChatAccessFrame::decode(&revoke),
        Err(ChatAccessFrameError::TrailingBytes)
    );
    let mut two = issue().encode().to_vec();
    two.push(0);
    assert_eq!(
        ChatAccessFrame::decode(&two),
        Err(ChatAccessFrameError::TrailingBytes)
    );
    for text in [
        String::new(),
        "nvt1_".to_owned(),
        "sk-live-real-key".to_owned(),
        "nvt1_abc=".to_owned(),
        "nvt1_ab cd".to_owned(),
        format!("nvt1_{}", "a".repeat(MAX_ACCESS_TOKEN_BYTES)),
    ] {
        assert_eq!(
            ChatAccessToken::new(text.clone()),
            Err(ChatAccessFrameError::Token),
            "{text}"
        );
    }
    let mut forged = issue().encode().to_vec();
    forged[24] = b'x';
    assert_eq!(
        ChatAccessFrame::decode(&forged),
        Err(ChatAccessFrameError::Token)
    );
}

#[test]
fn debug_output_never_shows_the_token() {
    let frame = issue();
    let text = format!("{frame:?} {:?}", token());
    assert!(!text.contains("nvt1_"), "{text}");
    assert!(!text.contains("Ab-_9"), "{text}");
    assert!(text.contains("redacted"));
    let mut decoder = ChatAccessDecoder::new();
    let bytes = frame.encode();
    let (_, _) = decoder.feed(&bytes[..40]).unwrap();
    assert!(!format!("{decoder:?}").contains("nvt1_"));
}
