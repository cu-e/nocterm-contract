use nocterm_hub_model::{Assurance, Role};

use crate::v1;

/// Wire value of a role.
pub fn role_to_wire(role: Role) -> v1::Role {
    match role {
        Role::Guest => v1::Role::Guest,
        Role::Member => v1::Role::Member,
        Role::Admin => v1::Role::Admin,
        Role::Owner => v1::Role::Owner,
    }
}

/// Role from its wire value; `None` for unspecified or unknown values.
pub fn role_from_wire(value: i32) -> Option<Role> {
    match v1::Role::try_from(value).ok()? {
        v1::Role::Unspecified => None,
        v1::Role::Guest => Some(Role::Guest),
        v1::Role::Member => Some(Role::Member),
        v1::Role::Admin => Some(Role::Admin),
        v1::Role::Owner => Some(Role::Owner),
    }
}

/// Wire value of an assurance level.
pub fn assurance_to_wire(assurance: Assurance) -> v1::Assurance {
    match assurance {
        Assurance::Software => v1::Assurance::Software,
        Assurance::Hardware => v1::Assurance::Hardware,
    }
}

/// Assurance from its wire value; unknown values count as the weaker level.
pub fn assurance_from_wire(value: i32) -> Assurance {
    match v1::Assurance::try_from(value) {
        Ok(v1::Assurance::Hardware) => Assurance::Hardware,
        _ => Assurance::Software,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_round_trip_through_the_wire() {
        for role in Role::ALL {
            assert_eq!(role_from_wire(role_to_wire(role) as i32), Some(role));
        }
        assert_eq!(role_from_wire(0), None);
        assert_eq!(role_from_wire(99), None);
    }

    #[test]
    fn the_descriptor_set_names_every_service() {
        use prost::Message;
        let set = prost_types_free_decode(super::super::FILE_DESCRIPTOR_SET);
        for service in [
            "AuthService",
            "DirectoryService",
            "StoreService",
            "SessionService",
            "LinkService",
            "RelayService",
            "FleetService",
            "NodeService",
            "AuditService",
        ] {
            assert!(set.contains(service), "missing {service}");
        }
        let _ = v1::Empty::default().encode_to_vec();
    }

    /// Avoids a prost-types dependency: service names appear verbatim in the encoding.
    fn prost_types_free_decode(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }
}
