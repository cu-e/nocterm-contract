use super::*;
use sha2::{Digest, Sha256};
type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fixture = (
    &'static str,
    ToolArguments<'static>,
    &'static str,
    &'static str,
);
const TRANSFER_ID: &str = "0a0b0c0d-0e0f-1011-1213-141516171819";
fn fixtures() -> Vec<Fixture> {
    let mut all = command_fixtures().to_vec();
    all.extend(transfer_fixtures());
    all
}
fn command_fixtures() -> [Fixture; 8] {
    [
        (
            "list_terminals",
            ToolArguments::ListTerminals,
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-list.hex"),
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-list.sha256"),
        ),
        (
            "open_terminal",
            ToolArguments::OpenTerminal {
                server_id: "server",
            },
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-open.hex"),
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-open.sha256"),
        ),
        (
            "read_terminal",
            ToolArguments::ReadTerminal {
                terminal_id: "terminal",
                lines: Some(10),
                since: None,
            },
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-read.hex"),
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-read.sha256"),
        ),
        (
            "send_input",
            ToolArguments::SendInput {
                terminal_id: "terminal",
                text: "literal input",
                press_enter: true,
            },
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-input.hex"),
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-input.sha256"),
        ),
        (
            "run_command",
            ToolArguments::RunCommand {
                terminal_id: "terminal",
                command: "pwd",
                timeout_ms: Some(1000),
                idle_ms: None,
            },
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-run.hex"),
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-run.sha256"),
        ),
        (
            "exec_command",
            ToolArguments::ExecCommand {
                terminal_id: "terminal",
                program: "/bin/printf",
                args: vec!["%s", "$(literal); *"],
                stdin: Some(""),
                timeout_ms: None,
                yield_ms: Some(0),
            },
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-exec.hex"),
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-exec.sha256"),
        ),
        (
            "read_command",
            ToolArguments::ReadCommand {
                terminal_id: "terminal",
                command_id: "command",
                yield_ms: Some(50),
            },
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-read-command.hex"),
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-read-command.sha256"),
        ),
        (
            "cancel_command",
            ToolArguments::CancelCommand {
                terminal_id: "terminal",
                command_id: "command",
            },
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-cancel.hex"),
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-cancel.sha256"),
        ),
    ]
}
fn transfer_fixtures() -> [Fixture; 3] {
    [
        (
            "transfer_files",
            ToolArguments::TransferFiles {
                source_terminal_id: "terminal",
                sources: vec!["/srv/a", "/srv/dir b"],
                destination_terminal_id: "terminal-2",
                destination: "/home/alice/in",
                overwrite: false,
                yield_ms: Some(1000),
            },
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-transfer.hex"),
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-transfer.sha256"),
        ),
        (
            "read_transfer",
            ToolArguments::ReadTransfer {
                transfer_id: TRANSFER_ID,
                yield_ms: None,
            },
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-read-transfer.hex"),
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-read-transfer.sha256"),
        ),
        (
            "cancel_transfer",
            ToolArguments::CancelTransfer {
                transfer_id: TRANSFER_ID,
            },
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-cancel-transfer.hex"),
            include_str!("../../../../../fixtures/cloud-payload-v1/tool-cancel-transfer.sha256"),
        ),
    ]
}
#[test]
fn every_tool_fingerprint_matches_independent_python_and_exact_argument_bytes() -> TestResult {
    for (name, arguments, fixture, digest) in fixtures() {
        let encoded = arguments.canonical_bytes()?;
        assert_eq!(arguments.name(), name);
        assert_eq!(encoded, hex::decode(fixture.trim())?);
        assert_eq!(hex::encode(arguments.digest()?), digest.trim());
        let direct: [u8; 32] = Sha256::digest(&encoded).into();
        assert_eq!(arguments.digest()?, direct);
    }
    Ok(())
}
#[test]
fn argument_fingerprints_distinguish_boundaries_options_targets_and_tool_purpose() -> TestResult {
    let first = ToolArguments::ExecCommand {
        terminal_id: "terminal",
        program: "p",
        args: vec!["a b"],
        stdin: None,
        timeout_ms: None,
        yield_ms: None,
    };
    let mut changed = first.clone();
    let ToolArguments::ExecCommand { args, .. } = &mut changed else {
        return Err("exec".into());
    };
    *args = vec!["a", "b"];
    assert_ne!(first.digest()?, changed.digest()?);
    let mut changed = first.clone();
    let ToolArguments::ExecCommand { stdin, .. } = &mut changed else {
        return Err("exec".into());
    };
    *stdin = Some("");
    assert_ne!(first.digest()?, changed.digest()?);
    let mut changed = first.clone();
    let ToolArguments::ExecCommand { yield_ms, .. } = &mut changed else {
        return Err("exec".into());
    };
    *yield_ms = Some(0);
    assert_ne!(first.digest()?, changed.digest()?);
    let read = ToolArguments::ReadCommand {
        terminal_id: "terminal",
        command_id: "command",
        yield_ms: None,
    };
    let cancel = ToolArguments::CancelCommand {
        terminal_id: "terminal",
        command_id: "command",
    };
    assert_ne!(read.digest()?, cancel.digest()?);
    assert!(!format!("{first:?}").contains("a b"));
    Ok(())
}
#[test]
fn fingerprints_reject_unbounded_collections_and_content_before_allocating_output() {
    let huge = "x".repeat(MAX_TOOL_ARGUMENT_BYTES);
    assert!(
        ToolArguments::SendInput {
            terminal_id: "terminal",
            text: &huge,
            press_enter: false
        }
        .digest()
        .is_err()
    );
    assert!(
        ToolArguments::ExecCommand {
            terminal_id: "terminal",
            program: "p",
            args: vec!["a"; 257],
            stdin: None,
            timeout_ms: None,
            yield_ms: None
        }
        .digest()
        .is_err()
    );
    assert!(
        ToolArguments::OpenTerminal { server_id: "" }
            .digest()
            .is_err()
    );
}

#[test]
fn decoder_preserves_every_canonical_argument_fixtures() -> TestResult {
    for (_, expected, encoded, _) in fixtures() {
        let bytes = hex::decode(encoded.trim())?;
        let actual = ToolArguments::from_canonical_bytes(&bytes)?;
        assert_eq!(actual, expected);
        assert_eq!(actual.canonical_bytes()?, bytes);
        for length in 0..bytes.len() {
            assert!(ToolArguments::from_canonical_bytes(&bytes[..length]).is_err());
        }
        let mut extra = bytes;
        extra.push(0);
        assert!(ToolArguments::from_canonical_bytes(&extra).is_err());
    }
    Ok(())
}

#[test]
fn decoder_refuses_unknown_flags_argument_counts_and_versions() -> TestResult {
    let mut input =
        hex::decode(include_str!("../../../../../fixtures/cloud-payload-v1/tool-exec.hex").trim())?;
    let count = 4
        + b"nocterm/cloud-tool-arguments/v1".len()
        + 1
        + 4
        + "terminal".len()
        + 4
        + "/bin/printf".len();
    input[count..count + 2].copy_from_slice(&257_u16.to_be_bytes());
    assert_eq!(
        ToolArguments::from_canonical_bytes(&input),
        Err(CommandError::Malformed)
    );
    let mut input = ToolArguments::SendInput {
        terminal_id: "t",
        text: "",
        press_enter: false,
    }
    .canonical_bytes()?;
    *input.last_mut().ok_or("missing flag")? = 2;
    assert_eq!(
        ToolArguments::from_canonical_bytes(&input),
        Err(CommandError::Malformed)
    );
    input[4] = b'X';
    assert_eq!(
        ToolArguments::from_canonical_bytes(&input),
        Err(CommandError::UnsupportedVersion)
    );
    assert_eq!(
        ToolArguments::from_canonical_bytes(&vec![0; MAX_TOOL_ARGUMENT_BYTES + 1]),
        Err(CommandError::PlaintextTooLarge),
    );
    Ok(())
}

#[test]
fn preflight_nested_arguments_write_every_variant_directly_into_the_outer_sink() -> TestResult {
    for (_, arguments, fixture, _) in fixtures() {
        let bytes = hex::decode(fixture.trim())?;
        let mut expected = u32::try_from(bytes.len())?.to_be_bytes().to_vec();
        expected.extend_from_slice(&bytes);
        let mut counter = BoundedWriter::counter(expected.len());
        arguments.write_field_to(&mut counter)?;
        assert_eq!(counter.len(), expected.len());
        let mut output = BoundedWriter::exact_buffer(counter.len());
        arguments.write_field_to(&mut output)?;
        assert_eq!(output.into_bytes()?, expected);
        let mut short = BoundedWriter::counter(expected.len() - 1);
        assert!(arguments.write_field_to(&mut short).is_err());
    }
    Ok(())
}

#[test]
fn preflight_nested_arguments_refuse_their_own_cap_before_touching_outer_output() -> TestResult {
    let text = "x".repeat(MAX_TOOL_ARGUMENT_BYTES);
    let arguments = ToolArguments::SendInput {
        terminal_id: "terminal",
        text: &text,
        press_enter: false,
    };
    let mut outer = BoundedWriter::buffer(usize::MAX);
    assert_eq!(
        arguments.write_field_to(&mut outer),
        Err(CommandError::PlaintextTooLarge)
    );
    assert_eq!(outer.len(), 0);
    assert!(outer.into_bytes()?.is_empty());
    Ok(())
}

fn transfer<'a>(sources: Vec<&'a str>, id: &'a str) -> ToolArguments<'a> {
    ToolArguments::TransferFiles {
        source_terminal_id: id,
        sources,
        destination_terminal_id: "destination",
        destination: "/in",
        overwrite: true,
        yield_ms: None,
    }
}

/// Hand-built tag 9 body, so the decoder is exercised without the encoder's own cap.
fn raw_transfer(count: u16) -> Vec<u8> {
    let field = |value: &str| {
        let mut out = u32::try_from(value.len())
            .unwrap_or(0)
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(value.as_bytes());
        out
    };
    let mut bytes = field("nocterm/cloud-tool-arguments/v1");
    bytes.push(9);
    bytes.extend(field("source"));
    bytes.extend(count.to_be_bytes());
    for _ in 0..count {
        bytes.extend(field("/a"));
    }
    bytes.extend(field("destination"));
    bytes.extend(field("/in"));
    bytes.push(1);
    bytes.push(0);
    bytes
}

#[test]
fn transfer_sources_accept_the_boundary_and_refuse_zero_or_too_many_in_both_directions()
-> TestResult {
    let accepted = transfer(vec!["/a"; MAX_TRANSFER_SOURCES], "source");
    let bytes = accepted.canonical_bytes()?;
    assert_eq!(bytes, raw_transfer(u16::try_from(MAX_TRANSFER_SOURCES)?));
    assert_eq!(ToolArguments::from_canonical_bytes(&bytes)?, accepted);
    for count in [0, MAX_TRANSFER_SOURCES + 1] {
        let refused = transfer(vec!["/a"; count], "source");
        assert_eq!(refused.canonical_bytes(), Err(CommandError::Malformed));
        assert_eq!(refused.digest(), Err(CommandError::Malformed));
        assert_eq!(
            ToolArguments::from_canonical_bytes(&raw_transfer(u16::try_from(count)?)),
            Err(CommandError::Malformed)
        );
    }
    Ok(())
}

#[test]
fn transfer_identities_are_bounded_and_transfer_tools_are_distinct_purposes() -> TestResult {
    let long = "x".repeat(129);
    for arguments in [
        transfer(vec!["/a"], ""),
        transfer(vec!["/a"], &long),
        ToolArguments::ReadTransfer {
            transfer_id: "",
            yield_ms: None,
        },
        ToolArguments::CancelTransfer { transfer_id: &long },
    ] {
        assert_eq!(arguments.digest(), Err(CommandError::IdentityLength));
    }
    let read = ToolArguments::ReadTransfer {
        transfer_id: "t",
        yield_ms: None,
    };
    let cancel = ToolArguments::CancelTransfer { transfer_id: "t" };
    assert_ne!(read.digest()?, cancel.digest()?);
    let mut keep = transfer(vec!["/a"], "source");
    let original = keep.digest()?;
    let ToolArguments::TransferFiles { overwrite, .. } = &mut keep else {
        return Err("transfer".into());
    };
    *overwrite = false;
    assert_ne!(original, keep.digest()?);
    Ok(())
}

#[test]
fn decoder_refuses_a_tag_after_the_last_known_tool_as_unsupported() -> TestResult {
    let mut bytes = ToolArguments::ListTerminals.canonical_bytes()?;
    *bytes.last_mut().ok_or("missing tag")? = 12;
    assert_eq!(
        ToolArguments::from_canonical_bytes(&bytes),
        Err(CommandError::UnsupportedKind)
    );
    Ok(())
}
