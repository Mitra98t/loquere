#![forbid(unsafe_code)]

//! Identità locale, account, inviti e certificati dei dispositivi.

mod account;
mod account_id;
mod certificate;
mod codec;
mod device_list;
mod error;
mod invite;

pub use account::Account;
pub use account_id::AccountId;
pub use certificate::{DeviceCert, DeviceRole};
pub use device_list::DeviceList;
pub use error::IdentityError;
pub use invite::{Invitation, InviteCandidate, InviteOptions};

pub(crate) use codec::take_array;
#[cfg(test)]
mod tests {
    use super::*;
    use loquere_crypto::{CryptoError, SecretKey};

    #[test]
    fn account_can_sign_and_verify_device_certificate() {
        let account_key = SecretKey::generate();
        let device_key = SecretKey::generate();
        let cert = DeviceCert::issue(
            &account_key,
            device_key.public_key(),
            "Computer di casa".to_owned(),
            DeviceRole::Admin,
            1_800_000_000,
        )
        .unwrap();

        assert_eq!(cert.verify(), Ok(()));
        assert_eq!(
            cert.account_id().to_bytes(),
            account_key.public_key().to_bytes()
        );
        assert_eq!(cert.device_id(), device_key.public_key());
        assert_eq!(cert.role(), DeviceRole::Admin);
    }

    #[test]
    fn certificate_fields_are_bound_to_the_signature() {
        let account_key = SecretKey::generate();
        let device_key = SecretKey::generate();
        let cert = DeviceCert::issue(
            &account_key,
            device_key.public_key(),
            "Laptop".to_owned(),
            DeviceRole::Member,
            42,
        )
        .unwrap();
        assert_eq!(
            {
                let mut bytes = cert.to_bytes();
                let name_offset = b"loquere:device-cert:v1\0".len() + 32 + 32 + 1 + 8 + 2;
                bytes[name_offset] ^= 1;
                DeviceCert::from_bytes(&bytes)
            },
            Err(IdentityError::Crypto(CryptoError::InvalidSignature))
        );
    }

    #[test]
    fn empty_or_unencodable_name_is_rejected() {
        let account_key = SecretKey::generate();
        let device_key = SecretKey::generate();

        assert_eq!(
            DeviceCert::issue(
                &account_key,
                device_key.public_key(),
                String::new(),
                DeviceRole::Admin,
                0,
            ),
            Err(IdentityError::InvalidName)
        );
    }

    #[test]
    fn role_encoding_rejects_unknown_values() {
        assert_eq!(DeviceRole::try_from(2), Err(IdentityError::InvalidRole));
    }

    #[test]
    fn certificate_encoding_round_trips_and_rejects_trailing_data() {
        let account_key = SecretKey::generate();
        let device_key = SecretKey::generate();
        let cert = DeviceCert::issue(
            &account_key,
            device_key.public_key(),
            "Dispositivo 🗝".to_owned(),
            DeviceRole::Member,
            u64::MAX,
        )
        .unwrap();
        let encoded = cert.to_bytes();

        assert_eq!(DeviceCert::from_bytes(&encoded), Ok(cert));
        let mut with_trailing_byte = encoded;
        with_trailing_byte.push(0);
        assert_eq!(
            DeviceCert::from_bytes(&with_trailing_byte),
            Err(IdentityError::InvalidEncoding)
        );
    }

    #[test]
    fn account_creation_issues_an_admin_device() {
        let account = Account::create("Primo dispositivo".to_owned(), 123).unwrap();

        assert_eq!(account.device_cert().verify(), Ok(()));
        assert_eq!(account.device_cert().role(), DeviceRole::Admin);
        assert_eq!(account.device_cert().account_id(), account.account_id());
        assert_eq!(
            account.device_cert().device_id(),
            account.device_public_key()
        );
    }

    #[test]
    fn account_id_base32_is_52_character_canonical_round_trip() {
        let account_id = AccountId(SecretKey::from_bytes([0x5a; 32]).public_key().to_bytes());
        let encoded = account_id.to_base32();

        assert_eq!(encoded.len(), 52);
        assert_eq!(AccountId::from_base32(&encoded), Ok(account_id));
        let mut noncanonical_padding = encoded.into_bytes();
        *noncanonical_padding.last_mut().unwrap() = b'B';
        let noncanonical_padding = String::from_utf8(noncanonical_padding).unwrap();
        assert_eq!(
            AccountId::from_base32(&noncanonical_padding),
            Err(IdentityError::InvalidEncoding)
        );
    }

    #[test]
    fn account_id_base32_rejects_wrong_length_and_alphabet() {
        assert_eq!(
            AccountId::from_base32("A"),
            Err(IdentityError::InvalidEncoding)
        );
        assert_eq!(
            AccountId::from_base32(&"!".repeat(52)),
            Err(IdentityError::InvalidEncoding)
        );
    }

    #[test]
    fn account_id_base32_matches_rfc4648_encoding() {
        let public_key = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let account_id = AccountId::from_bytes(public_key).unwrap();

        assert_eq!(
            account_id.to_base32(),
            "25NJQAMCWEFLPVKL73J4SZAHHIHOC4XT3KTCGJNPAINGR5YHKENA"
        );
    }

    #[test]
    fn account_identity_round_trips_through_encrypted_file() {
        let account = Account::create("PC casa".to_owned(), 500).unwrap();
        let id = account.account_id();
        let device = account.device_public_key();
        let discovery = *account.discovery_secret();
        let master_key = [0x42; 32];
        let encrypted = account.seal(&master_key).unwrap();
        let restored = Account::open(&encrypted, &master_key).unwrap();

        assert_eq!(restored.account_id(), id);
        assert_eq!(restored.device_public_key(), device);
        assert_eq!(*restored.discovery_secret(), discovery);
        assert_eq!(restored.device_cert().verify(), Ok(()));
        assert_eq!(
            restored.sign_as_account(b"test"),
            account.sign_as_account(b"test")
        );
    }

    #[test]
    fn encrypted_identity_rejects_wrong_master_key_and_tampering() {
        let account = Account::create("PC".to_owned(), 500).unwrap();
        let master_key = [0x24; 32];
        let mut encrypted = account.seal(&master_key).unwrap();

        assert!(matches!(
            Account::open(&encrypted, &[0x25; 32]),
            Err(IdentityError::Crypto(CryptoError::AuthenticationFailed))
        ));
        let last = encrypted.len() - 1;
        encrypted[last] ^= 1;
        assert!(Account::open(&encrypted, &master_key).is_err());
    }

    #[test]
    fn passphrase_protected_identity_uses_recoverable_envelope() {
        let account = Account::create("Portatile".to_owned(), 1000).unwrap();
        let id = account.account_id();
        let encrypted = account
            .protect_with_passphrase("corretta cavallo batteria")
            .unwrap();

        let restored =
            Account::unprotect_with_passphrase(&encrypted, "corretta cavallo batteria").unwrap();
        assert_eq!(restored.account_id(), id);
        assert!(matches!(
            Account::unprotect_with_passphrase(&encrypted, "password errata"),
            Err(IdentityError::Crypto(CryptoError::AuthenticationFailed))
        ));
    }

    #[test]
    fn storage_keys_are_domain_separated_and_survive_identity_unlock() {
        let account = Account::create("Dispositivo".to_owned(), 1000).unwrap();
        let first = account
            .derive_storage_key(b"loquere:mls:conversation-a:v1")
            .unwrap();
        let other = account
            .derive_storage_key(b"loquere:mls:conversation-b:v1")
            .unwrap();
        assert_ne!(*first, *other);

        let protected = account
            .protect_with_passphrase("corretta cavallo batteria")
            .unwrap();
        let restored =
            Account::unprotect_with_passphrase(&protected, "corretta cavallo batteria").unwrap();
        assert_eq!(
            *restored
                .derive_storage_key(b"loquere:mls:conversation-a:v1")
                .unwrap(),
            *first
        );
        assert_eq!(
            restored.device_public_key().to_bytes(),
            loquere_crypto::SecretKey::from_bytes(*restored.device_signing_key())
                .public_key()
                .to_bytes()
        );
        assert!(restored.derive_storage_key(b"").is_err());
    }

    #[test]
    fn invite_is_signed_and_round_trips_as_uri_and_text_code() {
        let account = Account::create("PC Alice".to_owned(), 100).unwrap();
        let invite = account
            .create_invite(
                "Alice".to_owned(),
                10_000,
                InviteOptions {
                    single_use: true,
                    auto_accept: false,
                },
                vec![
                    InviteCandidate {
                        address: "192.0.2.10".parse().unwrap(),
                        port: 4000,
                    },
                    InviteCandidate {
                        address: "2001:db8::5".parse().unwrap(),
                        port: 4001,
                    },
                ],
            )
            .unwrap();

        assert_eq!(invite.verify_at(9_999), Ok(()));
        assert_eq!(invite.verify_at(10_001), Err(IdentityError::ExpiredInvite));
        assert_eq!(
            Invitation::parse_code(&invite.to_uri().unwrap()),
            Ok(invite.clone())
        );
        assert_eq!(
            Invitation::parse_code(&invite.to_text_code().unwrap()),
            Ok(invite)
        );
    }

    #[test]
    fn invite_parser_rejects_signature_tampering_and_malformed_candidates() {
        let account = Account::create("PC Bob".to_owned(), 100).unwrap();
        let invite = account
            .create_invite(
                "Bob".to_owned(),
                0,
                InviteOptions {
                    single_use: false,
                    auto_accept: true,
                },
                vec![],
            )
            .unwrap();
        let mut bytes = invite.to_bytes().unwrap();
        bytes[1] ^= 1;
        assert!(Invitation::from_bytes(&bytes).is_err());
        assert!(Invitation::parse_code("loquere://invite/%%%bad").is_err());
        assert!(invite.verify_at(500_000).is_ok());
    }
}
