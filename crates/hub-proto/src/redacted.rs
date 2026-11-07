//! `Debug` of messages that carry secrets a person typed: they print as redacted, so a request
//! logged by mistake leaks no password, API key or private key.

use std::fmt;

use crate::v2;

macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => {
        $(
            impl fmt::Debug for v2::$name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str(concat!(stringify!($name), " { <redacted> }"))
                }
            }
        )+
    };
}

redacted_debug!(
    SshCredential,
    ProviderInput,
    SetupRequest,
    PasswordLoginRequest,
    RedeemInviteRequest,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_never_reach_debug_output() {
        let credential = v2::SshCredential {
            secret: Some(v2::ssh_credential::Secret::Password("hunter2".into())),
            passphrase: String::new(),
        };
        let printed = format!("{credential:?}");
        assert!(!printed.contains("hunter2"));
        assert!(printed.contains("redacted"));
    }
}
