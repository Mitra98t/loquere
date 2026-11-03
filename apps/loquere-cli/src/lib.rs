//! Comandi CLI di Loquere e formattazione dei relativi risultati.

use loquere_identity::Invitation;
use std::net::IpAddr;

/// Dati pubblici di un invito dopo la verifica crittografica.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InviteSummary {
    /// Account indicato nel certificato firmato.
    pub account_id: String,
    /// Nome suggerito da chi ha creato l'invito.
    pub display_name: String,
    /// Timestamp Unix; zero indica che l'invito non scade.
    pub expires_at: u32,
    /// Se il token è monouso.
    pub single_use: bool,
    /// Se il creatore consente l'accettazione automatica.
    pub auto_accept: bool,
    /// Candidati di rete inclusi nell'invito.
    pub candidates: Vec<InviteCandidateSummary>,
}

/// Indirizzo IP e porta pubblicati nell'invito.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InviteCandidateSummary {
    /// Indirizzo IP.
    pub address: IpAddr,
    /// Porta UDP.
    pub port: u16,
}

/// Decodifica un URI/codice invito e ne verifica firma e certificato.
pub fn inspect_invite(code: &str) -> Result<InviteSummary, loquere_identity::IdentityError> {
    let invite = Invitation::parse_code(code)?;
    let options = invite.options();
    Ok(InviteSummary {
        account_id: invite.account_id().to_base32(),
        display_name: invite.display_name().to_owned(),
        expires_at: invite.expires_at(),
        single_use: options.single_use,
        auto_accept: options.auto_accept,
        candidates: invite
            .candidates()
            .iter()
            .map(|candidate| InviteCandidateSummary {
                address: candidate.address,
                port: candidate.port,
            })
            .collect(),
    })
}

/// Formatta i dati verificati senza mai mostrare il token dell'invito.
pub fn format_invite(summary: &InviteSummary) -> String {
    let expiration = if summary.expires_at == 0 {
        "mai (timestamp 0)".to_owned()
    } else {
        format!("Unix {}", summary.expires_at)
    };
    let candidates = if summary.candidates.is_empty() {
        "  (nessuno)".to_owned()
    } else {
        summary
            .candidates
            .iter()
            .map(|candidate| format!("  {}:{}", candidate.address, candidate.port))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "Invito Loquere verificato\nAccount: {}\nNome: {}\nScadenza: {}\nMonouso: {}\nAccettazione automatica: {}\nCandidati UDP:\n{}",
        summary.account_id,
        summary.display_name,
        expiration,
        yes_no(summary.single_use),
        yes_no(summary.auto_accept),
        candidates,
    )
}

fn yes_no(value: bool) -> &'static str {
    if value { "sì" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loquere_identity::{Account, InviteCandidate, InviteOptions};

    #[test]
    fn invite_inspection_verifies_and_displays_public_fields_without_token() {
        let account = Account::create("Portatile Alice".to_owned(), 1).unwrap();
        let invite = account
            .create_invite(
                "Alice".to_owned(),
                1234,
                InviteOptions {
                    single_use: true,
                    auto_accept: false,
                },
                vec![InviteCandidate {
                    address: "192.0.2.4".parse().unwrap(),
                    port: 4567,
                }],
            )
            .unwrap();

        let summary = inspect_invite(&invite.to_uri().unwrap()).unwrap();
        let rendered = format_invite(&summary);
        assert_eq!(summary.account_id, account.account_id().to_base32());
        assert!(rendered.contains("192.0.2.4:4567"));
        assert!(rendered.contains("Monouso: sì"));
        assert!(!rendered.contains(&format!("{:?}", invite.token())));
    }

    #[test]
    fn invite_inspection_rejects_malformed_or_tampered_codes() {
        assert!(inspect_invite("loquere://invite/nope").is_err());
    }
}
