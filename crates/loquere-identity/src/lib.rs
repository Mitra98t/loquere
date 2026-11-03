#![forbid(unsafe_code)]

//! Identità locale, account e certificati dei dispositivi.

use loquere_crypto::{CryptoError, PassphraseEnvelope, PublicKey, SealedBox, SecretKey, Signature};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

const DEVICE_CERT_DOMAIN: &[u8] = b"loquere:device-cert:v1\0";
const INVITE_DOMAIN: &[u8] = b"loquere:invite:v1\0";

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

    /// Codifica l'identificatore in Base32 RFC 4648 senza padding (52 caratteri).
    pub fn to_base32(self) -> String {
        const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut output = String::with_capacity(52);
        let mut accumulator = 0u32;
        let mut bits = 0u8;
        for byte in self.0 {
            accumulator = (accumulator << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                output.push(ALPHABET[((accumulator >> bits) & 31) as usize] as char);
            }
        }
        if bits != 0 {
            output.push(ALPHABET[((accumulator << (5 - bits)) & 31) as usize] as char);
        }
        output
    }

    /// Decodifica Base32 RFC 4648 senza padding e rifiuta codifiche non canoniche.
    pub fn from_base32(value: &str) -> Result<Self, IdentityError> {
        if value.len() != 52 {
            return Err(IdentityError::InvalidEncoding);
        }
        let mut output = [0u8; 32];
        let mut output_len = 0usize;
        let mut accumulator = 0u32;
        let mut bits = 0u8;
        for byte in value.bytes() {
            let value = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'2'..=b'7' => byte - b'2' + 26,
                _ => return Err(IdentityError::InvalidEncoding),
            };
            accumulator = (accumulator << 5) | u32::from(value);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                if output_len >= output.len() {
                    return Err(IdentityError::InvalidEncoding);
                }
                output[output_len] = ((accumulator >> bits) & 0xff) as u8;
                output_len += 1;
            }
        }
        if output_len != 32 || bits != 4 || accumulator & 0x0f != 0 {
            return Err(IdentityError::InvalidEncoding);
        }
        Self::from_bytes(output).map_err(IdentityError::from)
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
    discovery_secret: Zeroizing<[u8; 32]>,
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
        let mut discovery_secret = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *discovery_secret);
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
            discovery_secret,
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

    /// Crea un invito firmato da questo dispositivo Admin.
    pub fn create_invite(
        &self,
        display_name: String,
        expires_at: u32,
        options: InviteOptions,
        candidates: Vec<InviteCandidate>,
    ) -> Result<Invitation, IdentityError> {
        Invitation::issue(
            &self.device_key,
            self.device_cert.clone(),
            display_name,
            expires_at,
            options,
            candidates,
        )
    }

    /// Segreto di scoperta dell'account (32 byte).
    pub fn discovery_secret(&self) -> &[u8; 32] {
        &self.discovery_secret
    }

    /// Serializza e cifra l'identità usando la chiave master `MK`.
    pub fn seal(&self, master_key: &[u8; 32]) -> Result<Vec<u8>, IdentityError> {
        let plaintext = self.encode_secret_state()?;
        let sealed = SealedBox::seal(master_key, &plaintext, b"loquere:identity:v1")?;
        Ok(sealed.to_bytes())
    }

    /// Apre un'identità cifrata e verifica la corrispondenza tra chiavi e certificato.
    pub fn open(encoded: &[u8], master_key: &[u8; 32]) -> Result<Self, IdentityError> {
        let sealed = SealedBox::from_bytes(encoded)?;
        let plaintext = sealed.open(master_key, b"loquere:identity:v1")?;
        Self::decode_secret_state(&plaintext)
    }

    /// Protegge l'identità con una MK casuale e avvolge la MK con Argon2id.
    pub fn protect_with_passphrase(&self, passphrase: &str) -> Result<Vec<u8>, IdentityError> {
        let mut master_key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *master_key);
        let encrypted_identity = self.seal(&master_key)?;
        let encrypted_master_key =
            PassphraseEnvelope::seal(passphrase, &*master_key, b"loquere:master-key:v1")?
                .to_bytes();
        let key_len = u32::try_from(encrypted_master_key.len())
            .map_err(|_| IdentityError::InvalidEncoding)?;
        let identity_len =
            u32::try_from(encrypted_identity.len()).map_err(|_| IdentityError::InvalidEncoding)?;
        let mut output =
            Vec::with_capacity(16 + encrypted_master_key.len() + encrypted_identity.len());
        output.extend_from_slice(b"LOQPRT\x01\0");
        output.extend_from_slice(&key_len.to_le_bytes());
        output.extend_from_slice(&identity_len.to_le_bytes());
        output.extend_from_slice(&encrypted_master_key);
        output.extend_from_slice(&encrypted_identity);
        Ok(output)
    }

    /// Sblocca un'identità protetta con passphrase.
    pub fn unprotect_with_passphrase(
        encoded: &[u8],
        passphrase: &str,
    ) -> Result<Self, IdentityError> {
        if encoded.len() < 16 || &encoded[..8] != b"LOQPRT\x01\0" {
            return Err(IdentityError::InvalidEncoding);
        }
        let key_len = u32::from_le_bytes(encoded[8..12].try_into().unwrap()) as usize;
        let identity_len = u32::from_le_bytes(encoded[12..16].try_into().unwrap()) as usize;
        let expected_len = 16usize
            .checked_add(key_len)
            .and_then(|len| len.checked_add(identity_len))
            .ok_or(IdentityError::InvalidEncoding)?;
        if encoded.len() != expected_len {
            return Err(IdentityError::InvalidEncoding);
        }
        let key_end = 16 + key_len;
        let encrypted_master_key = PassphraseEnvelope::from_bytes(&encoded[16..key_end])?;
        let master_key = encrypted_master_key.open(passphrase, b"loquere:master-key:v1")?;
        let master_key: Zeroizing<[u8; 32]> = Zeroizing::new(
            master_key
                .as_slice()
                .try_into()
                .map_err(|_| IdentityError::InvalidEncoding)?,
        );
        Self::open(&encoded[key_end..], &master_key)
    }

    fn encode_secret_state(&self) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
        let cert = self.device_cert.to_bytes();
        let cert_len = u32::try_from(cert.len()).map_err(|_| IdentityError::InvalidEncoding)?;
        let account_key = self.account_key.to_bytes();
        let device_key = self.device_key.to_bytes();
        let mut bytes = Zeroizing::new(Vec::with_capacity(8 + 32 * 3 + 4 + cert.len()));
        bytes.extend_from_slice(b"LOQID\x01\0\0");
        bytes.extend_from_slice(&*account_key);
        bytes.extend_from_slice(&*device_key);
        bytes.extend_from_slice(&*self.discovery_secret);
        bytes.extend_from_slice(&cert_len.to_le_bytes());
        bytes.extend_from_slice(&cert);
        Ok(bytes)
    }

    fn decode_secret_state(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() < 8 + 32 * 3 + 4 || &bytes[..8] != b"LOQID\x01\0\0" {
            return Err(IdentityError::InvalidEncoding);
        }
        let mut cursor = 8;
        let account_key = SecretKey::from_bytes(take_array(bytes, &mut cursor)?);
        let device_key = SecretKey::from_bytes(take_array(bytes, &mut cursor)?);
        let discovery_secret = Zeroizing::new(take_array(bytes, &mut cursor)?);
        let cert_len = u32::from_le_bytes(take_array(bytes, &mut cursor)?) as usize;
        if bytes.len() != cursor + cert_len {
            return Err(IdentityError::InvalidEncoding);
        }
        let device_cert = DeviceCert::from_bytes(&bytes[cursor..])?;
        if device_cert.account_id() != AccountId(account_key.public_key().to_bytes())
            || device_cert.device_id() != device_key.public_key()
            || device_cert.role() != DeviceRole::Admin
        {
            return Err(IdentityError::KeyMismatch);
        }
        Ok(Self {
            account_key,
            device_key,
            discovery_secret,
            device_cert,
        })
    }
}

/// Opzioni di consumo dell'invito.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InviteOptions {
    /// Il token può essere usato una sola volta.
    pub single_use: bool,
    /// Il destinatario può essere accettato automaticamente dal creatore.
    pub auto_accept: bool,
}

/// Candidato di rete condiviso dall'invito.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InviteCandidate {
    /// Indirizzo IP (gli IPv6 con scope locale non si rappresentano qui).
    pub address: core::net::IpAddr,
    /// Porta UDP.
    pub port: u16,
}

/// Invito firmato per il primo contatto tra due account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invitation {
    certificate: DeviceCert,
    token: [u8; 16],
    expires_at: u32,
    options: InviteOptions,
    display_name: String,
    candidates: Vec<InviteCandidate>,
    signature: Signature,
}

impl Invitation {
    fn issue(
        device_key: &SecretKey,
        certificate: DeviceCert,
        display_name: String,
        expires_at: u32,
        options: InviteOptions,
        candidates: Vec<InviteCandidate>,
    ) -> Result<Self, IdentityError> {
        validate_invite_fields(&display_name, &candidates)?;
        if device_key.public_key() != certificate.device_id() || certificate.verify().is_err() {
            return Err(IdentityError::KeyMismatch);
        }
        let mut token = [0u8; 16];
        OsRng.fill_bytes(&mut token);
        let mut invitation = Self {
            certificate,
            token,
            expires_at,
            options,
            display_name,
            candidates,
            signature: Signature::from_bytes([0; 64]),
        };
        invitation.signature = device_key.sign(&invitation.signing_bytes()?);
        Ok(invitation)
    }

    /// Verifica firma del dispositivo e certificato dell'account.
    pub fn verify(&self) -> Result<(), IdentityError> {
        validate_invite_fields(&self.display_name, &self.candidates)?;
        self.certificate.verify()?;
        self.certificate
            .device_id()
            .verify(&self.signing_bytes()?, &self.signature)?;
        Ok(())
    }

    /// Verifica firma e scadenza rispetto all'orologio iniettato dal chiamante.
    pub fn verify_at(&self, now: u32) -> Result<(), IdentityError> {
        self.verify()?;
        if self.expires_at != 0 && now > self.expires_at {
            return Err(IdentityError::ExpiredInvite);
        }
        Ok(())
    }

    /// Token casuale che autorizza il primo contatto.
    pub const fn token(&self) -> [u8; 16] {
        self.token
    }

    /// Istante Unix di scadenza; zero significa nessuna scadenza.
    pub const fn expires_at(&self) -> u32 {
        self.expires_at
    }

    /// Opzioni dell'invito.
    pub const fn options(&self) -> InviteOptions {
        self.options
    }

    /// Nome suggerito dal creatore.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Candidati di rete inclusi nell'invito.
    pub fn candidates(&self) -> &[InviteCandidate] {
        &self.candidates
    }

    /// Account identificato dall'invito.
    pub const fn account_id(&self) -> AccountId {
        self.certificate.account_id()
    }

    /// Codifica binaria canonica, inclusa la firma del dispositivo.
    pub fn to_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(&self.signature.to_bytes());
        Ok(bytes)
    }

    /// Decodifica e verifica firma e certificato.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() < 1 + 32 + 32 + 2 + 16 + 4 + 1 + 1 + 1 + 64 || bytes[0] != 1 {
            return Err(IdentityError::InvalidEncoding);
        }
        let mut cursor = 1;
        let account_id = AccountId::from_bytes(take_array(bytes, &mut cursor)?)?;
        let device_id = PublicKey::from_bytes(take_array(bytes, &mut cursor)?)?;
        let certificate_len = u16::from_le_bytes(take_array(bytes, &mut cursor)?) as usize;
        let cert_end = cursor
            .checked_add(certificate_len)
            .ok_or(IdentityError::InvalidEncoding)?;
        let certificate = DeviceCert::from_bytes(
            bytes
                .get(cursor..cert_end)
                .ok_or(IdentityError::InvalidEncoding)?,
        )?;
        if certificate.account_id() != account_id || certificate.device_id() != device_id {
            return Err(IdentityError::KeyMismatch);
        }
        cursor = cert_end;
        let token = take_array(bytes, &mut cursor)?;
        let expires_at = u32::from_le_bytes(take_array(bytes, &mut cursor)?);
        let flag_byte = take_array::<1>(bytes, &mut cursor)?[0];
        if flag_byte & !0b11 != 0 {
            return Err(IdentityError::InvalidEncoding);
        }
        let options = InviteOptions {
            single_use: flag_byte & 1 != 0,
            auto_accept: flag_byte & 2 != 0,
        };
        let display_len = take_array::<1>(bytes, &mut cursor)?[0] as usize;
        let display_end = cursor
            .checked_add(display_len)
            .ok_or(IdentityError::InvalidEncoding)?;
        let display_name = core::str::from_utf8(
            bytes
                .get(cursor..display_end)
                .ok_or(IdentityError::InvalidEncoding)?,
        )
        .map_err(|_| IdentityError::InvalidEncoding)?
        .to_owned();
        cursor = display_end;
        let candidate_count = take_array::<1>(bytes, &mut cursor)?[0] as usize;
        if candidate_count > 4 {
            return Err(IdentityError::InvalidEncoding);
        }
        let mut candidates = Vec::with_capacity(candidate_count);
        for _ in 0..candidate_count {
            let family = take_array::<1>(bytes, &mut cursor)?[0];
            let address = take_array::<16>(bytes, &mut cursor)?;
            let port = u16::from_be_bytes(take_array(bytes, &mut cursor)?);
            let address = match family {
                4 if address[4..].iter().all(|byte| *byte == 0) => core::net::IpAddr::V4(
                    core::net::Ipv4Addr::new(address[0], address[1], address[2], address[3]),
                ),
                6 => core::net::IpAddr::V6(core::net::Ipv6Addr::from(address)),
                _ => return Err(IdentityError::InvalidEncoding),
            };
            candidates.push(InviteCandidate { address, port });
        }
        let signature = Signature::from_bytes(take_array(bytes, &mut cursor)?);
        if cursor != bytes.len() {
            return Err(IdentityError::InvalidEncoding);
        }
        let invitation = Self {
            certificate,
            token,
            expires_at,
            options,
            display_name,
            candidates,
            signature,
        };
        invitation.verify()?;
        Ok(invitation)
    }

    /// Link `loquere://invite/...` pronto da condividere.
    pub fn to_uri(&self) -> Result<String, IdentityError> {
        Ok(format!(
            "loquere://invite/{}",
            base32_encode(&self.to_bytes()?)
        ))
    }

    /// Codice testuale `TC1-...` per canali che non supportano schemi URI.
    pub fn to_text_code(&self) -> Result<String, IdentityError> {
        Ok(format!("TC1-{}", base32_encode(&self.to_bytes()?)))
    }

    /// Accetta il link URI o il codice testuale dell'invito.
    pub fn parse_code(value: &str) -> Result<Self, IdentityError> {
        let payload = value
            .strip_prefix("loquere://invite/")
            .or_else(|| value.strip_prefix("TC1-"))
            .ok_or(IdentityError::InvalidEncoding)?;
        Self::from_bytes(&base32_decode(payload)?)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let mut bytes = INVITE_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.unsigned_bytes()?);
        Ok(bytes)
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        validate_invite_fields(&self.display_name, &self.candidates)?;
        let cert = self.certificate.to_bytes();
        let cert_len = u16::try_from(cert.len()).map_err(|_| IdentityError::InvalidEncoding)?;
        let mut bytes = Vec::new();
        bytes.push(1);
        bytes.extend_from_slice(&self.certificate.account_id().to_bytes());
        bytes.extend_from_slice(&self.certificate.device_id().to_bytes());
        bytes.extend_from_slice(&cert_len.to_le_bytes());
        bytes.extend_from_slice(&cert);
        bytes.extend_from_slice(&self.token);
        bytes.extend_from_slice(&self.expires_at.to_le_bytes());
        bytes.push(u8::from(self.options.single_use) | (u8::from(self.options.auto_accept) << 1));
        bytes.push(self.display_name.len() as u8);
        bytes.extend_from_slice(self.display_name.as_bytes());
        bytes.push(self.candidates.len() as u8);
        for candidate in &self.candidates {
            match candidate.address {
                core::net::IpAddr::V4(address) => {
                    bytes.push(4);
                    bytes.extend_from_slice(&address.octets());
                    bytes.extend_from_slice(&[0; 12]);
                }
                core::net::IpAddr::V6(address) => {
                    bytes.push(6);
                    bytes.extend_from_slice(&address.octets());
                }
            }
            bytes.extend_from_slice(&candidate.port.to_be_bytes());
        }
        Ok(bytes)
    }
}

fn validate_invite_fields(
    display_name: &str,
    candidates: &[InviteCandidate],
) -> Result<(), IdentityError> {
    if display_name.len() > 32
        || candidates.len() > 4
        || candidates.iter().any(|item| item.port == 0)
    {
        return Err(IdentityError::InvalidEncoding);
    }
    Ok(())
}

fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((accumulator >> bits) & 31) as usize] as char);
        }
    }
    if bits != 0 {
        output.push(ALPHABET[((accumulator << (5 - bits)) & 31) as usize] as char);
    }
    output
}

fn base32_decode(value: &str) -> Result<Vec<u8>, IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::InvalidEncoding);
    }
    let mut output = Vec::with_capacity(value.len() * 5 / 8);
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in value.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(IdentityError::InvalidEncoding),
        };
        accumulator = (accumulator << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || accumulator & ((1 << bits) - 1) != 0 {
        return Err(IdentityError::InvalidEncoding);
    }
    Ok(output)
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
    /// Chiavi private non corrispondenti al certificato dell'identità.
    KeyMismatch,
    /// Invito scaduto secondo l'orologio fornito dal chiamante.
    ExpiredInvite,
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
            Self::KeyMismatch => formatter.write_str("chiavi non corrispondenti all'identità"),
            Self::ExpiredInvite => formatter.write_str("invito scaduto"),
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
