use serde::{Deserialize, Serialize};

/// How well a device protects its keys at rest. Reported at registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Assurance {
    /// Keys are protected by file permissions only.
    Software,
    /// Keys are sealed by a TPM, Secure Enclave or an equivalent.
    Hardware,
}

impl Assurance {
    /// Stable lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Assurance::Software => "software",
            Assurance::Hardware => "hardware",
        }
    }

    /// Parses the stable name; unknown values are treated as the weaker level.
    pub fn parse_lenient(s: &str) -> Self {
        if s == "hardware" {
            Assurance::Hardware
        } else {
            Assurance::Software
        }
    }
}
