//! Borrowed inverse of the canonical fingerprint layout.
use super::{MAX_TOOL_ARGUMENT_BYTES, MAX_TRANSFER_SOURCES, ToolArguments};
use crate::cloud::{CommandError, codec::Reader};

pub(super) fn read(bytes: &[u8]) -> Result<ToolArguments<'_>, CommandError> {
    if bytes.len() > MAX_TOOL_ARGUMENT_BYTES {
        return Err(CommandError::PlaintextTooLarge);
    }
    let mut input = ArgumentsReader(Reader::new(bytes));
    if input.0.field(64)? != b"nocterm/cloud-tool-arguments/v1" {
        return Err(CommandError::UnsupportedVersion);
    }
    let result = input.arguments()?;
    input.0.finish()?;
    Ok(result)
}
struct ArgumentsReader<'a>(Reader<'a>);
impl<'a> ArgumentsReader<'a> {
    fn text(&mut self) -> Result<&'a str, CommandError> {
        core::str::from_utf8(self.0.field(MAX_TOOL_ARGUMENT_BYTES)?)
            .map_err(|_| CommandError::Malformed)
    }
    fn id(&mut self) -> Result<&'a str, CommandError> {
        let value = self.text()?;
        if value.is_empty() || value.len() > 128 {
            return Err(CommandError::IdentityLength);
        }
        Ok(value)
    }
    fn flag(&mut self) -> Result<bool, CommandError> {
        match self.0.array::<1>()? {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => Err(CommandError::Malformed),
        }
    }
    fn number(&mut self) -> Result<Option<u64>, CommandError> {
        if self.flag()? {
            Ok(Some(u64::from_be_bytes(self.0.array()?)))
        } else {
            Ok(None)
        }
    }
    fn optional_text(&mut self) -> Result<Option<&'a str>, CommandError> {
        if self.flag()? {
            Ok(Some(self.text()?))
        } else {
            Ok(None)
        }
    }
    fn argv(&mut self) -> Result<Vec<&'a str>, CommandError> {
        let count = usize::from(u16::from_be_bytes(self.0.array()?));
        if count > 256 {
            return Err(CommandError::Malformed);
        }
        (0..count).map(|_| self.text()).collect()
    }
    fn sources(&mut self) -> Result<Vec<&'a str>, CommandError> {
        let count = usize::from(u16::from_be_bytes(self.0.array()?));
        if count == 0 || count > MAX_TRANSFER_SOURCES {
            return Err(CommandError::Malformed);
        }
        (0..count).map(|_| self.text()).collect()
    }
    fn arguments(&mut self) -> Result<ToolArguments<'a>, CommandError> {
        Ok(match self.0.array::<1>()? {
            [1] => ToolArguments::ListTerminals,
            [2] => ToolArguments::OpenTerminal {
                server_id: self.id()?,
            },
            [3] => ToolArguments::ReadTerminal {
                terminal_id: self.id()?,
                lines: self.number()?,
                since: self.number()?,
            },
            [4] => ToolArguments::SendInput {
                terminal_id: self.id()?,
                text: self.text()?,
                press_enter: self.flag()?,
            },
            [5] => ToolArguments::RunCommand {
                terminal_id: self.id()?,
                command: self.text()?,
                timeout_ms: self.number()?,
                idle_ms: self.number()?,
            },
            [6] => ToolArguments::ExecCommand {
                terminal_id: self.id()?,
                program: self.text()?,
                args: self.argv()?,
                stdin: self.optional_text()?,
                timeout_ms: self.number()?,
                yield_ms: self.number()?,
            },
            [7] => ToolArguments::ReadCommand {
                terminal_id: self.id()?,
                command_id: self.id()?,
                yield_ms: self.number()?,
            },
            [8] => ToolArguments::CancelCommand {
                terminal_id: self.id()?,
                command_id: self.id()?,
            },
            [9] => ToolArguments::TransferFiles {
                source_terminal_id: self.id()?,
                sources: self.sources()?,
                destination_terminal_id: self.id()?,
                destination: self.text()?,
                overwrite: self.flag()?,
                yield_ms: self.number()?,
            },
            [10] => ToolArguments::ReadTransfer {
                transfer_id: self.id()?,
                yield_ms: self.number()?,
            },
            [11] => ToolArguments::CancelTransfer {
                transfer_id: self.id()?,
            },
            _ => return Err(CommandError::UnsupportedKind),
        })
    }
}
