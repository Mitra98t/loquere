use crate::{
    AccountId, DeviceCert, DeviceList, DeviceRole, IdentityError, Invitation, InviteCandidate,
    InviteOptions, take_array,
};
use hkdf::Hkdf;
use loquere_crypto::{PassphraseEnvelope, PublicKey, SealedBox, SecretKey, Signature};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Nuovo account con il primo dispositivo amministratore.
pub struct Account {
    account_key: SecretKey,
    device_key: SecretKey,
    master_key: Zeroizing<[u8; 32]>,
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
        let mut master_key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *master_key);
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
            master_key,
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

    /// Copia azzerabile della chiave privata del dispositivo, per inizializzare
    /// protocolli che firmano a nome del dispositivo (ad esempio MLS).
    pub fn device_signing_key(&self) -> Zeroizing<[u8; 32]> {
        self.device_key.to_bytes()
    }

    /// Deriva una chiave d'archiviazione dedicata dal master key locale.
    /// `purpose` deve essere un'etichetta stabile e non vuota, per esempio
    /// `loquere:mls:<conversation-id>:v1`.
    pub fn derive_storage_key(&self, purpose: &[u8]) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
        if purpose.is_empty() || purpose.len() > 200 {
            return Err(IdentityError::InvalidEncoding);
        }
        let hkdf = Hkdf::<Sha256>::new(Some(b"loquere:storage-key:v1"), &*self.master_key);
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf.expand(purpose, &mut *key)
            .map_err(|_| IdentityError::InvalidEncoding)?;
        Ok(key)
    }

    /// Firma un contenuto con la chiave dell'account.
    pub fn sign_as_account(&self, message: &[u8]) -> Signature {
        self.account_key.sign(message)
    }

    /// Firma la lista iniziale con il primo dispositivo, solo per il bootstrap.
    /// Non usare per sostituire una lista esistente o azzerarne la sequenza.
    pub fn initial_device_list(&self) -> Result<DeviceList, IdentityError> {
        DeviceList::issue(&self.account_key, 0, vec![self.device_cert.clone()], vec![])
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
        let mut account = Self::decode_secret_state(&plaintext)?;
        account.master_key = Zeroizing::new(*master_key);
        Ok(account)
    }

    /// Protegge l'identità con una MK casuale e avvolge la MK con Argon2id.
    pub fn protect_with_passphrase(&self, passphrase: &str) -> Result<Vec<u8>, IdentityError> {
        let encrypted_identity = self.seal(&self.master_key)?;
        let encrypted_master_key =
            PassphraseEnvelope::seal(passphrase, &*self.master_key, b"loquere:master-key:v1")?
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
            master_key: Zeroizing::new([0u8; 32]),
            discovery_secret,
            device_cert,
        })
    }
}
