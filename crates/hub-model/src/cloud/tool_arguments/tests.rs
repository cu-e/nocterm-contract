use super::*;
use sha2::{Digest, Sha256};
type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fixture = (
    &'static str,
    ToolArguments<'static>,
    &'static str,
    &'static str,
);
fn fixtures() -> [Fixture; 8] {
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
#[test]
fn eight_tool_fingerprints_match_independent_python_and_exact_argument_bytes() -> TestResult {
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
fn decoder_preserves_all_eight_canonical_argument_fixtures() -> TestResult {
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
fn preflight_nested_arguments_write_all_eight_variants_directly_into_the_outer_sink() -> TestResult
{
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
