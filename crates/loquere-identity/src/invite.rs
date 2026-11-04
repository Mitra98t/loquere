use crate::{AccountId, DeviceCert, DeviceList, IdentityError, take_array};
use loquere_crypto::{PublicKey, SecretKey, Signature};
use rand_core::{OsRng, RngCore};

const INVITE_DOMAIN: &[u8] = b"loquere:invite:v1\0";

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
    pub(crate) fn issue(
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

    /// Identificatore del dispositivo che ha firmato l'invito.
    pub fn device_id(&self) -> PublicKey {
        self.certificate.device_id()
    }

    /// Verifica che l'invito ancora valido, il peer TLS autenticato e la lista
    /// firmata si riferiscano allo stesso dispositivo attivo dell'account.
    /// Non approva l'amicizia e non verifica il consumo del token o il consenso.
    pub fn validate_peer_list(
        &self,
        now: u32,
        authenticated_peer: &[u8; 32],
        devices: &DeviceList,
    ) -> Result<(), IdentityError> {
        self.verify_at(now)?;
        if devices.account_id() != self.account_id()
            || self.device_id().to_bytes() != *authenticated_peer
            || !devices.contains_device(authenticated_peer)
        {
            return Err(IdentityError::KeyMismatch);
        }
        Ok(())
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
