//! Stable fingerprints of exact semantic tool arguments, independent of JSON key order.
//! Execution validation remains the terminal catalog's responsibility. Encoding a value
//! never authorizes a target, consumes a grant or approves an operation.
use super::{CommandError, codec::BoundedWriter};
use core::fmt;
mod reader;

pub const MAX_TOOL_ARGUMENT_BYTES: usize = 128 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub enum ToolArguments<'a> {
    ListTerminals,
    OpenTerminal {
        server_id: &'a str,
    },
    ReadTerminal {
        terminal_id: &'a str,
        lines: Option<u64>,
        since: Option<u64>,
    },
    SendInput {
        terminal_id: &'a str,
        text: &'a str,
        press_enter: bool,
    },
    RunCommand {
        terminal_id: &'a str,
        command: &'a str,
        timeout_ms: Option<u64>,
        idle_ms: Option<u64>,
    },
    ExecCommand {
        terminal_id: &'a str,
        program: &'a str,
        args: Vec<&'a str>,
        stdin: Option<&'a str>,
        timeout_ms: Option<u64>,
        yield_ms: Option<u64>,
    },
    ReadCommand {
        terminal_id: &'a str,
        command_id: &'a str,
        yield_ms: Option<u64>,
    },
    CancelCommand {
        terminal_id: &'a str,
        command_id: &'a str,
    },
}
impl<'a> ToolArguments<'a> {
    /// Decode exact bounded semantic arguments. These historical/display values
    /// never authorize execution; the native terminal catalog validates calls.
    pub fn from_canonical_bytes(bytes: &'a [u8]) -> Result<Self, CommandError> {
        reader::read(bytes)
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::ListTerminals => "list_terminals",
            Self::OpenTerminal { .. } => "open_terminal",
            Self::ReadTerminal { .. } => "read_terminal",
            Self::SendInput { .. } => "send_input",
            Self::RunCommand { .. } => "run_command",
            Self::ExecCommand { .. } => "exec_command",
            Self::ReadCommand { .. } => "read_command",
            Self::CancelCommand { .. } => "cancel_command",
        }
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CommandError> {
        let mut writer = ArgumentWriter::buffer();
        self.encode(&mut writer)?;
        writer.output.into_bytes()
    }
    /// Hashes without allocating a second copy of command text/stdin.
    pub fn digest(&self) -> Result<[u8; 32], CommandError> {
        let mut writer = ArgumentWriter::hasher();
        self.encode(&mut writer)?;
        writer.output.into_digest()
    }
    fn encode(&self, writer: &mut ArgumentWriter) -> Result<(), CommandError> {
        writer.output.field(b"nocterm/cloud-tool-arguments/v1")?;
        match self {
            Self::ListTerminals => writer.tag(1),
            Self::OpenTerminal { server_id } => {
                writer.tag(2)?;
                writer.id(server_id)
            }
            Self::ReadTerminal {
                terminal_id,
                lines,
                since,
            } => {
                writer.tag(3)?;
                writer.id(terminal_id)?;
                writer.number(*lines)?;
                writer.number(*since)
            }
            Self::SendInput {
                terminal_id,
                text,
                press_enter,
            } => {
                writer.tag(4)?;
                writer.id(terminal_id)?;
                writer.text(text)?;
                writer.tag(u8::from(*press_enter))
            }
            Self::RunCommand {
                terminal_id,
                command,
                timeout_ms,
                idle_ms,
            } => {
                writer.tag(5)?;
                writer.id(terminal_id)?;
                writer.text(command)?;
                writer.number(*timeout_ms)?;
                writer.number(*idle_ms)
            }
            Self::ExecCommand {
                terminal_id,
                program,
                args,
                stdin,
                timeout_ms,
                yield_ms,
            } => {
                if args.len() > 256 {
                    return Err(CommandError::Malformed);
                }
                writer.tag(6)?;
                writer.id(terminal_id)?;
                writer.text(program)?;
                writer.output.extend(
                    &u16::try_from(args.len())
                        .map_err(|_| CommandError::Malformed)?
                        .to_be_bytes(),
                )?;
                for arg in args {
                    writer.text(arg)?;
                }
                writer.tag(u8::from(stdin.is_some()))?;
                if let Some(stdin) = stdin {
                    writer.text(stdin)?;
                }
                writer.number(*timeout_ms)?;
                writer.number(*yield_ms)
            }
            Self::ReadCommand {
                terminal_id,
                command_id,
                yield_ms,
            } => {
                writer.tag(7)?;
                writer.id(terminal_id)?;
                writer.id(command_id)?;
                writer.number(*yield_ms)
            }
            Self::CancelCommand {
                terminal_id,
                command_id,
            } => {
                writer.tag(8)?;
                writer.id(terminal_id)?;
                writer.id(command_id)
            }
        }
    }
}
impl fmt::Debug for ToolArguments<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolArguments")
            .field("name", &self.name())
            .finish_non_exhaustive()
    }
}

struct ArgumentWriter {
    output: BoundedWriter,
}
impl ArgumentWriter {
    fn buffer() -> Self {
        Self {
            output: BoundedWriter::buffer(MAX_TOOL_ARGUMENT_BYTES),
        }
    }
    fn hasher() -> Self {
        Self {
            output: BoundedWriter::hasher(MAX_TOOL_ARGUMENT_BYTES),
        }
    }
    fn tag(&mut self, value: u8) -> Result<(), CommandError> {
        self.output.extend(&[value])
    }
    fn id(&mut self, value: &str) -> Result<(), CommandError> {
        if value.is_empty() || value.len() > 128 {
            return Err(CommandError::IdentityLength);
        }
        self.text(value)
    }
    fn text(&mut self, value: &str) -> Result<(), CommandError> {
        self.output.field(value.as_bytes())
    }
    fn number(&mut self, value: Option<u64>) -> Result<(), CommandError> {
        self.tag(u8::from(value.is_some()))?;
        if let Some(value) = value {
            self.output.extend(&value.to_be_bytes())?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests;
