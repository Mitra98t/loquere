use loquere_crypto::CryptoError;

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
            Self::InvalidEncoding => formatter.write_str("codifica identità non valida"),
            Self::KeyMismatch => formatter.write_str("chiavi non corrispondenti all'identità"),
            Self::ExpiredInvite => formatter.write_str("invito scaduto"),
            Self::Crypto(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for IdentityError {}
