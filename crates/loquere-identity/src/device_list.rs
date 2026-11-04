use crate::{AccountId, DeviceCert, IdentityError, take_array};
use loquere_crypto::{SecretKey, Signature};

const DOMAIN: &[u8] = b"loquere:device-list:v1\0";
const MAX_DEVICES: usize = 256;
const MAX_BYTES: usize = 1024 * 1024;

/// Lista dispositivi firmata dall'account. Il controllo anti-rollback e la
/// decisione di amicizia spettano al chiamante, non a questa struttura.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceList {
    account: AccountId,
    sequence: u64,
    devices: Vec<DeviceCert>,
    revoked: Vec<[u8; 32]>,
    signature: Signature,
}

impl DeviceList {
    /// Firma una lista canonica; le chiavi duplicate o revocate sono rifiutate.
    pub fn issue(
        key: &SecretKey,
        sequence: u64,
        mut devices: Vec<DeviceCert>,
        mut revoked: Vec<[u8; 32]>,
    ) -> Result<Self, IdentityError> {
        devices.sort_by_key(|cert| cert.device_id().to_bytes());
        revoked.sort_unstable();
        let account = AccountId::from_bytes(key.public_key().to_bytes())?;
        let mut list = Self {
            account,
            sequence,
            devices,
            revoked,
            signature: key.sign(b""),
        };
        list.validate()?;
        let bytes = list.signing_bytes()?;
        list.signature = key.sign(&bytes);
        Ok(list)
    }

    fn validate(&self) -> Result<(), IdentityError> {
        if self.devices.len() > MAX_DEVICES || self.revoked.len() > MAX_DEVICES {
            return Err(IdentityError::InvalidEncoding);
        }
        let mut previous = None;
        for cert in &self.devices {
            cert.verify()?;
            let id = cert.device_id().to_bytes();
            if cert.account_id() != self.account
                || previous.is_some_and(|prev| prev >= id)
                || self.revoked.binary_search(&id).is_ok()
            {
                return Err(IdentityError::InvalidEncoding);
            }
            previous = Some(id);
        }
        if self.revoked.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(IdentityError::InvalidEncoding);
        }
        Ok(())
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(&self.account.to_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes.extend_from_slice(&(self.devices.len() as u16).to_le_bytes());
        for cert in &self.devices {
            let encoded = cert.to_bytes();
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&encoded);
            if bytes.len() > MAX_BYTES - 64 {
                return Err(IdentityError::InvalidEncoding);
            }
        }
        bytes.extend_from_slice(&(self.revoked.len() as u16).to_le_bytes());
        for id in &self.revoked {
            bytes.extend_from_slice(id);
        }
        if bytes.len() > MAX_BYTES - 64 {
            return Err(IdentityError::InvalidEncoding);
        }
        Ok(bytes)
    }

    /// Serializza la lista firmata.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.signing_bytes().expect("lista già validata");
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes
    }

    /// Decodifica e verifica lista, certificati e firma dell'account.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() > MAX_BYTES || !bytes.starts_with(DOMAIN) {
            return Err(IdentityError::InvalidEncoding);
        }
        let mut cursor = DOMAIN.len();
        let account = AccountId::from_bytes(take_array(bytes, &mut cursor)?)?;
        let sequence = u64::from_le_bytes(take_array(bytes, &mut cursor)?);
        let count = u16::from_le_bytes(take_array(bytes, &mut cursor)?) as usize;
        if count > MAX_DEVICES {
            return Err(IdentityError::InvalidEncoding);
        }
        let mut devices = Vec::with_capacity(count);
        for _ in 0..count {
            let len = u32::from_le_bytes(take_array(bytes, &mut cursor)?) as usize;
            let end = cursor
                .checked_add(len)
                .ok_or(IdentityError::InvalidEncoding)?;
            let cert = DeviceCert::from_bytes(
                bytes
                    .get(cursor..end)
                    .ok_or(IdentityError::InvalidEncoding)?,
            )?;
            devices.push(cert);
            cursor = end;
        }
        let count = u16::from_le_bytes(take_array(bytes, &mut cursor)?) as usize;
        if count > MAX_DEVICES {
            return Err(IdentityError::InvalidEncoding);
        }
        let mut revoked = Vec::with_capacity(count);
        for _ in 0..count {
            revoked.push(take_array(bytes, &mut cursor)?);
        }
        let signature = Signature::from_bytes(take_array(bytes, &mut cursor)?);
        if cursor != bytes.len() {
            return Err(IdentityError::InvalidEncoding);
        }
        let list = Self {
            account,
            sequence,
            devices,
            revoked,
            signature,
        };
        list.validate()?;
        list.account
            .public_key()?
            .verify(&bytes[..bytes.len() - 64], &signature)?;
        Ok(list)
    }

    /// Account firmatario.
    pub fn account_id(&self) -> AccountId {
        self.account
    }
    /// Numero di sequenza: il chiamante deve respingere rollback ed equivoci.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Certificati dei dispositivi attivi.
    pub fn devices(&self) -> &[DeviceCert] {
        &self.devices
    }
    /// Verifica solo la presenza nella lista, non l'amicizia o la freschezza.
    pub fn contains_device(&self, id: &[u8; 32]) -> bool {
        self.devices
            .binary_search_by_key(id, |cert| cert.device_id().to_bytes())
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceRole;

    #[test]
    fn signed_lists_validate_and_reject_tampering_and_revocation() {
        let account = SecretKey::generate();
        let device = SecretKey::generate();
        let cert = DeviceCert::issue(
            &account,
            device.public_key(),
            "Laptop".into(),
            DeviceRole::Member,
            0,
        )
        .unwrap();
        let id = device.public_key().to_bytes();
        let list = DeviceList::issue(&account, 4, vec![cert.clone()], vec![]).unwrap();
        assert_eq!(DeviceList::from_bytes(&list.to_bytes()), Ok(list.clone()));
        assert!(list.contains_device(&id));
        assert!(DeviceList::issue(&account, 5, vec![cert.clone()], vec![id]).is_err());
        assert!(DeviceList::issue(&account, 5, vec![cert.clone(), cert], vec![]).is_err());
        let removed = DeviceList::issue(&account, 5, vec![], vec![id]).unwrap();
        assert!(!removed.contains_device(&id));
        let mut encoded = list.to_bytes();
        encoded[DOMAIN.len() + 32] ^= 1;
        assert!(DeviceList::from_bytes(&encoded).is_err());
        for end in 0..encoded.len() {
            assert!(DeviceList::from_bytes(&encoded[..end]).is_err());
        }
    }
}
