#![forbid(unsafe_code)]

//! Log append-only di record cifrati, senza database o runtime asincroni.

use loquere_crypto::{CryptoError, SealedBox};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

const RECORD_AAD: &[u8] = b"loquere:store-record:v1\0";
const MAX_RECORD_SIZE: usize = 16 * 1024 * 1024;
static NEXT_COMPACTION_TEMP: AtomicU64 = AtomicU64::new(0);

/// Log aperto; ogni record viene cifrato con un nonce indipendente e legato alla
/// sua posizione tramite i dati associati autenticati.
pub struct RecordLog {
    file: File,
    key: Zeroizing<[u8; 32]>,
    next_sequence: u64,
    poisoned: bool,
    path: PathBuf,
    latest_record: Option<Zeroizing<Vec<u8>>>,
}

/// Log aperto e record decifrati in ordine di sequenza.
pub struct OpenedLog {
    /// Handle per aggiungere nuovi record.
    pub log: RecordLog,
    /// Record ricostruiti; il contenuto viene azzerato al rilascio.
    pub records: Vec<Zeroizing<Vec<u8>>>,
}

impl RecordLog {
    /// Apre o crea il log, decifra i record validi e scarta solo una coda
    /// chiaramente incompleta lasciata da un'interruzione durante la scrittura.
    pub fn open(path: impl AsRef<Path>, key: [u8; 32]) -> Result<OpenedLog, StoreError> {
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let path = path.as_ref().to_path_buf();
        let mut file = options.open(&path)?;
        let key = Zeroizing::new(key);
        let file_len = file.metadata()?.len();
        let mut offset = 0u64;
        let mut sequence = 0u64;
        let mut records = Vec::new();

        while offset < file_len {
            file.seek(SeekFrom::Start(offset))?;
            let mut length_bytes = [0u8; 4];
            match file.read_exact(&mut length_bytes) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(error) => return Err(StoreError::Io(error)),
            }
            let body_len = u32::from_le_bytes(length_bytes) as usize;
            if !(29..=MAX_RECORD_SIZE).contains(&body_len) {
                return Err(StoreError::InvalidRecordLength(body_len));
            }
            let body_start = offset + 4;
            let body_end = body_start
                .checked_add(body_len as u64)
                .ok_or(StoreError::InvalidRecordLength(body_len))?;
            if body_end > file_len {
                break;
            }
            let mut body = vec![0u8; body_len];
            file.read_exact(&mut body)?;
            let sealed = SealedBox::from_bytes(&body)?;
            let aad = record_aad(sequence);
            let plaintext = sealed.open(&key, &aad)?;
            records.push(plaintext);
            sequence = sequence
                .checked_add(1)
                .ok_or(StoreError::SequenceExhausted)?;
            offset = body_end;
        }

        if offset != file_len {
            file.set_len(offset)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;
        let latest_record = records.last().map(|record| Zeroizing::new(record.to_vec()));
        Ok(OpenedLog {
            log: Self {
                file,
                key,
                next_sequence: sequence,
                poisoned: false,
                path,
                latest_record,
            },
            records,
        })
    }

    /// Cifra e aggiunge un record, poi forza i dati su disco prima di ritornare.
    pub fn append(&mut self, plaintext: &[u8]) -> Result<u64, StoreError> {
        if self.poisoned {
            return Err(StoreError::NeedsRecovery);
        }
        if plaintext.len() > MAX_RECORD_SIZE - 29 {
            return Err(StoreError::InvalidRecordLength(plaintext.len()));
        }
        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(StoreError::SequenceExhausted)?;
        let aad = record_aad(sequence);
        let sealed = SealedBox::seal(&self.key, plaintext, &aad)?;
        let body = sealed.to_bytes();
        let length =
            u32::try_from(body.len()).map_err(|_| StoreError::InvalidRecordLength(body.len()))?;
        let result = (|| {
            self.file.seek(SeekFrom::End(0))?;
            self.file.write_all(&length.to_le_bytes())?;
            self.file.write_all(&body)?;
            self.file.sync_data()
        })();
        if let Err(error) = result {
            self.poisoned = true;
            return Err(StoreError::Io(error));
        }
        self.next_sequence = next_sequence;
        self.latest_record = Some(Zeroizing::new(plaintext.to_vec()));
        Ok(sequence)
    }

    /// Compatta il log conservando solo l'ultimo record autenticato.
    /// Scrive e sincronizza prima un file temporaneo, quindi lo sostituisce:
    /// un'interruzione prima della rinomina lascia intatto il log precedente.
    pub fn compact(self) -> Result<Self, StoreError> {
        if self.poisoned {
            return Err(StoreError::NeedsRecovery);
        }
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("loquere-log");
        let sequence = NEXT_COMPACTION_TEMP.fetch_add(1, Ordering::Relaxed);
        let temporary_path = parent.join(format!(
            ".{file_name}.{}.{}.compact",
            std::process::id(),
            sequence
        ));
        let mut temporary_options = OpenOptions::new();
        temporary_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            temporary_options.mode(0o600);
        }
        temporary_options.open(&temporary_path)?;

        let Self {
            file,
            key,
            path,
            latest_record,
            ..
        } = self;
        file.sync_all()?;
        drop(file);

        let rewrite = (|| {
            let mut replacement = Self::open(&temporary_path, *key)?.log;
            if let Some(record) = latest_record.as_deref() {
                replacement.append(record)?;
            }
            drop(replacement);
            std::fs::rename(&temporary_path, &path)?;
            #[cfg(unix)]
            File::open(parent)?.sync_all()?;
            Ok::<(), StoreError>(())
        })();
        if let Err(error) = rewrite {
            let _ = std::fs::remove_file(&temporary_path);
            return Err(error);
        }
        Self::open(&path, *key).map(|opened| opened.log)
    }

    /// Numero di sequenza del prossimo record.
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
}

fn record_aad(sequence: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECORD_AAD.len() + 8);
    aad.extend_from_slice(RECORD_AAD);
    aad.extend_from_slice(&sequence.to_le_bytes());
    aad
}

/// Errori del log locale.
#[derive(Debug)]
pub enum StoreError {
    /// Errore del filesystem.
    Io(io::Error),
    /// Errore di autenticazione o decodifica crittografica.
    Crypto(CryptoError),
    /// Lunghezza impossibile o oltre il limite per record.
    InvalidRecordLength(usize),
    /// Sequenza esaurita.
    SequenceExhausted,
    /// Il log ha avuto un errore di scrittura e deve essere riaperto per il recupero.
    NeedsRecovery,
}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<CryptoError> for StoreError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "errore I/O nel log: {error}"),
            Self::Crypto(error) => write!(formatter, "record cifrato non valido: {error}"),
            Self::InvalidRecordLength(length) => {
                write!(formatter, "lunghezza record non valida: {length}")
            }
            Self::SequenceExhausted => formatter.write_str("sequenza record esaurita"),
            Self::NeedsRecovery => formatter.write_str("riaprire il log per recuperare la coda"),
        }
    }
}

impl std::error::Error for StoreError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    struct TestFile(std::path::PathBuf);

    impl TestFile {
        fn new() -> Self {
            let id = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            Self(
                std::env::temp_dir().join(format!("loquere-store-{}-{id}.log", std::process::id())),
            )
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn records_round_trip_in_order_across_reopen() {
        let path = TestFile::new();
        let key = [0x42; 32];
        let opened = RecordLog::open(&path.0, key).unwrap();
        assert!(opened.records.is_empty());
        let mut log = opened.log;
        assert_eq!(log.append(b"primo").unwrap(), 0);
        assert_eq!(log.append(b"secondo").unwrap(), 1);
        drop(log);

        let opened = RecordLog::open(&path.0, key).unwrap();
        assert_eq!(opened.log.next_sequence(), 2);
        assert_eq!(&*opened.records[0], b"primo");
        assert_eq!(&*opened.records[1], b"secondo");
    }

    #[test]
    fn compaction_preserves_latest_record_and_resets_sequence() {
        let path = TestFile::new();
        let key = [0x61; 32];
        let mut log = RecordLog::open(&path.0, key).unwrap().log;
        log.append(b"obsolete snapshot one").unwrap();
        log.append(b"obsolete snapshot two").unwrap();
        log.append(b"latest snapshot").unwrap();

        let compacted = log.compact().unwrap();
        assert_eq!(compacted.next_sequence(), 1);
        drop(compacted);

        let reopened = RecordLog::open(&path.0, key).unwrap();
        assert_eq!(reopened.records.len(), 1);
        assert_eq!(&*reopened.records[0], b"latest snapshot");
        assert_eq!(reopened.log.next_sequence(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn newly_created_log_is_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;

        let path = TestFile::new();
        let _opened = RecordLog::open(&path.0, [0x31; 32]).unwrap();
        let mode = std::fs::metadata(&path.0).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn incomplete_tail_is_truncated_without_losing_committed_records() {
        let path = TestFile::new();
        let key = [0x17; 32];
        let opened = RecordLog::open(&path.0, key).unwrap();
        let mut log = opened.log;
        log.append(b"durable").unwrap();
        drop(log);
        let valid_len = std::fs::metadata(&path.0).unwrap().len();
        let mut file = OpenOptions::new().append(true).open(&path.0).unwrap();
        file.write_all(&100u32.to_le_bytes()).unwrap();
        file.write_all(b"short").unwrap();
        drop(file);

        let opened = RecordLog::open(&path.0, key).unwrap();
        assert_eq!(opened.records.len(), 1);
        assert_eq!(&*opened.records[0], b"durable");
        assert_eq!(std::fs::metadata(&path.0).unwrap().len(), valid_len);
        assert_eq!(opened.log.next_sequence(), 1);
    }

    #[test]
    fn wrong_key_or_modified_committed_record_is_not_silently_discarded() {
        let path = TestFile::new();
        let key = [0x91; 32];
        let opened = RecordLog::open(&path.0, key).unwrap();
        let mut log = opened.log;
        log.append(b"record").unwrap();
        drop(log);
        assert!(matches!(
            RecordLog::open(&path.0, [0x92; 32]),
            Err(StoreError::Crypto(_))
        ));

        let mut bytes = std::fs::read(&path.0).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&path.0, bytes).unwrap();
        assert!(matches!(
            RecordLog::open(&path.0, key),
            Err(StoreError::Crypto(_))
        ));
    }
}
