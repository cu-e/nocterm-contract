use nocterm_hub_model::Assurance;

use crate::v2;

/// Wire value of an assurance level.
pub fn assurance_to_wire(assurance: Assurance) -> v2::Assurance {
    match assurance {
        Assurance::Software => v2::Assurance::Software,
        Assurance::Hardware => v2::Assurance::Hardware,
    }
}

/// Assurance from its wire value; unknown values count as the weaker level.
pub fn assurance_from_wire(value: i32) -> Assurance {
    match v2::Assurance::try_from(value) {
        Ok(v2::Assurance::Hardware) => Assurance::Hardware,
        _ => Assurance::Software,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assurance_round_trips_through_the_wire() {
        for assurance in [Assurance::Software, Assurance::Hardware] {
            assert_eq!(
                assurance_from_wire(assurance_to_wire(assurance) as i32),
                assurance
            );
        }
        assert_eq!(assurance_from_wire(99), Assurance::Software);
    }

    #[test]
    fn the_descriptor_set_names_every_service() {
        let set = String::from_utf8_lossy(super::super::FILE_DESCRIPTOR_SET).into_owned();
        for service in [
            "AuthService",
            "AccountService",
            "VaultService",
            "RelayService",
            "AgentService",
            "ServerService",
            "ChatService",
        ] {
            assert!(set.contains(service), "missing {service}");
        }
    }
}
