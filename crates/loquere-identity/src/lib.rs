#![forbid(unsafe_code)]

//! Identità locale, account e certificati dei dispositivi.

use loquere_crypto::{CryptoError, PublicKey, SecretKey, Signature};

const DEVICE_CERT_DOMAIN: &[u8] = b"loquere:device-cert:v1\0";

/// Identificatore dell'account: la chiave pubblica Ed25519 dell'account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountId([u8; 32]);

impl AccountId {
    /// Crea un identificatore da una chiave pubblica valida.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        PublicKey::from_bytes(bytes)?;
        Ok(Self(bytes))
    }

    /// Restituisce i byte dell'identificatore.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Restituisce la chiave pubblica dell'account.
    pub fn public_key(self) -> Result<PublicKey, CryptoError> {
        PublicKey::from_bytes(self.0)
    }
}

/// Ruolo assegnato a un dispositivo nell'account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DeviceRole {
    /// Custodisce la chiave dell'account e può amministrare i dispositivi.
    Admin = 0,
    /// Non custodisce la chiave dell'account.
    Member = 1,
}

impl TryFrom<u8> for DeviceRole {
    type Error = IdentityError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Admin),
            1 => Ok(Self::Member),
            _ => Err(IdentityError::InvalidRole),
        }
    }
}

/// Certificato firmato dall'account che lega un dispositivo a un ruolo.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceCert {
    account_id: AccountId,
    device_id: PublicKey,
    name: String,
    role: DeviceRole,
    created_at: u64,
    signature: Signature,
}

impl DeviceCert {
    /// Firma un certificato usando la chiave privata dell'account.
    pub fn issue(
        account_key: &SecretKey,
        device_id: PublicKey,
        name: String,
        role: DeviceRole,
        created_at: u64,
    ) -> Result<Self, IdentityError> {
        validate_name(&name)?;
        let account_id = AccountId(account_key.public_key().to_bytes());
        let bytes = cert_signing_bytes(account_id, device_id, &name, role, created_at);
        let signature = account_key.sign(&bytes);
        Ok(Self {
            account_id,
            device_id,
            name,
            role,
            created_at,
            signature,
        })
    }

    /// Verifica firma e coerenza del certificato.
    pub fn verify(&self) -> Result<(), IdentityError> {
        validate_name(&self.name)?;
        self.account_id.public_key()?.verify(
            &cert_signing_bytes(
                self.account_id,
                self.device_id,
                &self.name,
                self.role,
                self.created_at,
            ),
            &self.signature,
        )?;
        Ok(())
    }

    /// Codifica il certificato includendo la firma, in forma canonica.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = cert_signing_bytes(
            self.account_id,
            self.device_id,
            &self.name,
            self.role,
            self.created_at,
        );
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes
    }

    /// Decodifica e verifica un certificato ricevuto.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let fixed_len = DEVICE_CERT_DOMAIN.len() + 32 + 32 + 1 + 8 + 2 + 64;
        if bytes.len() < fixed_len || !bytes.starts_with(DEVICE_CERT_DOMAIN) {
            return Err(IdentityError::InvalidEncoding);
        }
        let mut cursor = DEVICE_CERT_DOMAIN.len();
        let account_id = AccountId::from_bytes(take_array::<32>(bytes, &mut cursor)?)?;
        let device_id = PublicKey::from_bytes(take_array::<32>(bytes, &mut cursor)?)?;
        let role = DeviceRole::try_from(take_array::<1>(bytes, &mut cursor)?[0])?;
        let created_at = u64::from_le_bytes(take_array(bytes, &mut cursor)?);
        let name_len = u16::from_le_bytes(take_array(bytes, &mut cursor)?) as usize;
        if name_len == 0 || bytes.len() != cursor + name_len + 64 {
            return Err(IdentityError::InvalidEncoding);
        }
        let name = core::str::from_utf8(&bytes[cursor..cursor + name_len])
            .map_err(|_| IdentityError::InvalidEncoding)?
            .to_owned();
        cursor += name_len;
        let signature = Signature::from_bytes(take_array(bytes, &mut cursor)?);
        let cert = Self {
            account_id,
            device_id,
            name,
            role,
            created_at,
            signature,
        };
        cert.verify()?;
        Ok(cert)
    }

    /// Identità dell'account che ha firmato il certificato.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Identità pubblica del dispositivo.
    pub const fn device_id(&self) -> PublicKey {
        self.device_id
    }

    /// Nome visualizzato del dispositivo.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Ruolo del dispositivo.
    pub const fn role(&self) -> DeviceRole {
        self.role
    }

    /// Istante di creazione in secondi Unix.
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Firma dell'account.
    pub const fn signature(&self) -> Signature {
        self.signature
    }
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], IdentityError> {
    let end = cursor
        .checked_add(N)
        .ok_or(IdentityError::InvalidEncoding)?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or(IdentityError::InvalidEncoding)?;
    let array = slice
        .try_into()
        .map_err(|_| IdentityError::InvalidEncoding)?;
    *cursor = end;
    Ok(array)
}

/// Nuovo account con il primo dispositivo amministratore.
pub struct Account {
    account_key: SecretKey,
    device_key: SecretKey,
    device_cert: DeviceCert,
}

impl Account {
    /// Crea un account e il relativo primo dispositivo Admin.
    ///
    /// `created_at` è fornito dal chiamante per mantenere l'orologio fuori
    /// dalla logica di identità.
    pub fn create(device_name: String, created_at: u64) -> Result<Self, IdentityError> {
        let account_key = SecretKey::generate();
        let device_key = SecretKey::generate();
        let device_cert = DeviceCert::issue(
            &account_key,
            device_key.public_key(),
            device_name,
            DeviceRole::Admin,
            created_at,
        )?;
        Ok(Self {
            account_key,
            device_key,
            device_cert,
        })
    }

    /// Identificatore pubblico dell'account.
    pub const fn account_id(&self) -> AccountId {
        self.device_cert.account_id()
    }

    /// Certificato del primo dispositivo.
    pub const fn device_cert(&self) -> &DeviceCert {
        &self.device_cert
    }

    /// Chiave pubblica del primo dispositivo.
    pub fn device_public_key(&self) -> PublicKey {
        self.device_key.public_key()
    }

    /// Firma un contenuto con la chiave dell'account.
    pub fn sign_as_account(&self, message: &[u8]) -> Signature {
        self.account_key.sign(message)
    }
}

fn validate_name(name: &str) -> Result<(), IdentityError> {
    if name.is_empty() || name.len() > u16::MAX as usize {
        return Err(IdentityError::InvalidName);
    }
    Ok(())
}

fn cert_signing_bytes(
    account_id: AccountId,
    device_id: PublicKey,
    name: &str,
    role: DeviceRole,
    created_at: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DEVICE_CERT_DOMAIN.len() + 32 + 32 + 1 + 8 + 2 + name.len());
    bytes.extend_from_slice(DEVICE_CERT_DOMAIN);
    bytes.extend_from_slice(&account_id.0);
    bytes.extend_from_slice(&device_id.to_bytes());
    bytes.push(role as u8);
    bytes.extend_from_slice(&created_at.to_le_bytes());
    bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
    bytes.extend_from_slice(name.as_bytes());
    bytes
}

/// Errori di validazione dell'identità.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// Nome vuoto oppure troppo lungo per la codifica canonica.
    InvalidName,
    /// Byte di ruolo non riconosciuto.
    InvalidRole,
    /// Codifica troncata, non canonica o malformata.
    InvalidEncoding,
    /// Errore proveniente dalla verifica della chiave o della firma.
    Crypto(CryptoError),
}

impl From<CryptoError> for IdentityError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidName => formatter.write_str("nome dispositivo non valido"),
            Self::InvalidRole => formatter.write_str("ruolo dispositivo non valido"),
            Self::InvalidEncoding => formatter.write_str("codifica DeviceCert non valida"),
            Self::Crypto(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut cert = DeviceCert::issue(
            &account_key,
            device_key.public_key(),
            "Laptop".to_owned(),
            DeviceRole::Member,
            42,
        )
        .unwrap();
        cert.name = "Nome alterato".to_owned();

        assert_eq!(
            cert.verify(),
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
}
