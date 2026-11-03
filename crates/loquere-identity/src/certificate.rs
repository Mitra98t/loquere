use crate::{AccountId, IdentityError, take_array};
use loquere_crypto::{PublicKey, SecretKey, Signature};

const DEVICE_CERT_DOMAIN: &[u8] = b"loquere:device-cert:v1\0";

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
