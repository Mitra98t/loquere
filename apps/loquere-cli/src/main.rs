use std::process::ExitCode;
use std::{collections::BTreeMap, io::Write};

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("errore: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    match (args.next().as_deref(), args.next().as_deref()) {
        (Some("id"), Some("show")) => {
            let option = args.next();
            if option.as_deref() != Some("--file") {
                return Err(usage());
            }
            let path = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            let passphrase = loquere_cli::prompt_passphrase().map_err(|error| error.to_string())?;
            let summary = loquere_cli::inspect_identity_file(path, &passphrase)
                .map_err(|error| error.to_string())?;
            println!("{}", loquere_cli::format_identity(&summary));
            Ok(())
        }
        (Some("id"), Some("new")) => {
            let mut name = None;
            let mut output = None;
            while let Some(option) = args.next() {
                let value = args
                    .next()
                    .ok_or_else(|| format!("valore mancante per {option}\n{}", usage()))?;
                let slot = match option.as_str() {
                    "--name" => &mut name,
                    "--output" => &mut output,
                    _ => return Err(usage()),
                };
                if slot.replace(value).is_some() {
                    return Err(format!("opzione duplicata: {option}"));
                }
            }
            let name = name.ok_or_else(usage)?;
            let output = output.ok_or_else(usage)?;
            let passphrase = loquere_cli::prompt_passphrase().map_err(|error| error.to_string())?;
            let created_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| format!("orologio di sistema non valido: {error}"))?
                .as_secs();
            let account_id =
                loquere_cli::create_identity_file(output, name, &passphrase, created_at)
                    .map_err(|error| error.to_string())?;
            println!("Account creato: {account_id}");
            Ok(())
        }
        (Some("invite"), Some("create")) => {
            let mut file = None;
            let mut name = None;
            let mut expires_in = None;
            while let Some(option) = args.next() {
                let value = args
                    .next()
                    .ok_or_else(|| format!("valore mancante per {option}\n{}", usage()))?;
                let slot = match option.as_str() {
                    "--file" => &mut file,
                    "--name" => &mut name,
                    "--expires-in" => &mut expires_in,
                    _ => return Err(usage()),
                };
                if slot.replace(value).is_some() {
                    return Err(format!("opzione duplicata: {option}"));
                }
            }
            let file = file.ok_or_else(usage)?;
            let name = name.ok_or_else(usage)?;
            let duration = parse_duration(expires_in.as_deref().unwrap_or("7d"))?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| format!("orologio di sistema non valido: {error}"))?
                .as_secs();
            let expires_at = now
                .checked_add(duration)
                .and_then(|timestamp| u32::try_from(timestamp).ok())
                .ok_or_else(|| "scadenza oltre il limite rappresentabile".to_owned())?;
            let passphrase = loquere_cli::prompt_passphrase().map_err(|error| error.to_string())?;
            let code = loquere_cli::create_invite_from_file(file, &passphrase, name, expires_at)
                .map_err(|error| error.to_string())?;
            println!("{code}");
            Ok(())
        }
        (Some("invite"), Some("inspect")) => {
            let code = args.next().ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            let summary = loquere_cli::inspect_invite(&code)
                .map_err(|error| format!("invito non valido: {error}"))?;
            println!("{}", loquere_cli::format_invite(&summary));
            Ok(())
        }
        (Some("chat"), Some("init")) => {
            let (identity_file, state_file) = parse_chat_paths(args)?;
            let passphrase =
                loquere_cli::prompt_existing_passphrase().map_err(|error| error.to_string())?;
            let summary = loquere_cli::create_chat_state(identity_file, &passphrase, state_file)
                .map_err(|error| error.to_string())?;
            println!(
                "Gruppo MLS creato\nID: {}\nEpoch: {}",
                summary.group_id, summary.epoch
            );
            Ok(())
        }
        (Some("chat"), Some("show")) => {
            let (identity_file, state_file) = parse_chat_paths(args)?;
            let passphrase =
                loquere_cli::prompt_existing_passphrase().map_err(|error| error.to_string())?;
            let summary = loquere_cli::inspect_chat_state(identity_file, &passphrase, state_file)
                .map_err(|error| error.to_string())?;
            println!(
                "Conversazione MLS\nID: {}\nEpoch: {}",
                summary.group_id, summary.epoch
            );
            Ok(())
        }
        (Some("chat"), Some("key-package")) => {
            let options =
                parse_chat_options(args, &["--identity-file", "--state-file", "--output"])?;
            let passphrase =
                loquere_cli::prompt_existing_passphrase().map_err(|error| error.to_string())?;
            let package = loquere_cli::create_chat_key_package(
                required_option(&options, "--identity-file")?,
                &passphrase,
                required_option(&options, "--state-file")?,
            )
            .map_err(|error| error.to_string())?;
            let output = required_option(&options, "--output")?;
            write_new_file(output, &package)?;
            println!(
                "KeyPackage MLS salvato in {output}; trasferiscilo all'amministratore del gruppo."
            );
            Ok(())
        }
        (Some("chat"), Some("add-member")) => {
            let options = parse_chat_options(
                args,
                &[
                    "--identity-file",
                    "--state-file",
                    "--key-package",
                    "--welcome-out",
                    "--tree-out",
                    "--commit-out",
                ],
            )?;
            let package = std::fs::read(required_option(&options, "--key-package")?)
                .map_err(|error| error.to_string())?;
            let passphrase =
                loquere_cli::prompt_existing_passphrase().map_err(|error| error.to_string())?;
            let result = loquere_cli::add_chat_member(
                required_option(&options, "--identity-file")?,
                &passphrase,
                required_option(&options, "--state-file")?,
                &package,
            )
            .map_err(|error| error.to_string())?;
            write_new_file(required_option(&options, "--welcome-out")?, &result.welcome)?;
            write_new_file(
                required_option(&options, "--tree-out")?,
                &result.ratchet_tree,
            )?;
            write_new_file(required_option(&options, "--commit-out")?, &result.commit)?;
            println!("Membro aggiunto; consegna Welcome, tree e commit secondo il flusso MLS.");
            Ok(())
        }
        (Some("chat"), Some("join")) => {
            let options = parse_chat_options(
                args,
                &["--identity-file", "--state-file", "--welcome", "--tree"],
            )?;
            let welcome = std::fs::read(required_option(&options, "--welcome")?)
                .map_err(|error| error.to_string())?;
            let tree = std::fs::read(required_option(&options, "--tree")?)
                .map_err(|error| error.to_string())?;
            let passphrase =
                loquere_cli::prompt_existing_passphrase().map_err(|error| error.to_string())?;
            let summary = loquere_cli::join_chat_state(
                required_option(&options, "--identity-file")?,
                &passphrase,
                required_option(&options, "--state-file")?,
                &welcome,
                &tree,
            )
            .map_err(|error| error.to_string())?;
            println!(
                "Join MLS completato\nID: {}\nEpoch: {}",
                summary.group_id, summary.epoch
            );
            Ok(())
        }
        (Some("chat"), Some("apply-commit")) => {
            let options =
                parse_chat_options(args, &["--identity-file", "--state-file", "--commit"])?;
            let commit = std::fs::read(required_option(&options, "--commit")?)
                .map_err(|error| error.to_string())?;
            let passphrase =
                loquere_cli::prompt_existing_passphrase().map_err(|error| error.to_string())?;
            let summary = loquere_cli::apply_chat_commit(
                required_option(&options, "--identity-file")?,
                &passphrase,
                required_option(&options, "--state-file")?,
                &commit,
            )
            .map_err(|error| error.to_string())?;
            println!("Commit MLS applicato; epoch {}", summary.epoch);
            Ok(())
        }
        (Some("chat"), Some("send")) => {
            let options = parse_chat_options(
                args,
                &["--identity-file", "--state-file", "--message", "--output"],
            )?;
            let passphrase =
                loquere_cli::prompt_existing_passphrase().map_err(|error| error.to_string())?;
            let ciphertext = loquere_cli::encrypt_chat_message(
                required_option(&options, "--identity-file")?,
                &passphrase,
                required_option(&options, "--state-file")?,
                required_option(&options, "--message")?.as_bytes(),
            )
            .map_err(|error| error.to_string())?;
            let output = required_option(&options, "--output")?;
            write_new_file(output, &ciphertext)?;
            println!("Messaggio MLS cifrato in {output}; trasferisci il file al gruppo.");
            Ok(())
        }
        (Some("chat"), Some("receive")) => {
            let options =
                parse_chat_options(args, &["--identity-file", "--state-file", "--input"])?;
            let ciphertext = std::fs::read(required_option(&options, "--input")?)
                .map_err(|error| error.to_string())?;
            let passphrase =
                loquere_cli::prompt_existing_passphrase().map_err(|error| error.to_string())?;
            let plaintext = loquere_cli::decrypt_chat_message(
                required_option(&options, "--identity-file")?,
                &passphrase,
                required_option(&options, "--state-file")?,
                &ciphertext,
            )
            .map_err(|error| error.to_string())?;
            let plaintext = String::from_utf8(plaintext)
                .map_err(|_| "il testo decifrato non è UTF-8".to_owned())?;
            println!("{plaintext}");
            Ok(())
        }
        (Some("--help" | "-h"), _) | (None, _) => {
            println!("{}", usage());
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn parse_chat_paths(args: impl Iterator<Item = String>) -> Result<(String, String), String> {
    let options = parse_chat_options(args, &["--identity-file", "--state-file"])?;
    Ok((
        required_option(&options, "--identity-file")?.to_owned(),
        required_option(&options, "--state-file")?.to_owned(),
    ))
}

fn parse_chat_options(
    mut args: impl Iterator<Item = String>,
    allowed: &[&str],
) -> Result<BTreeMap<String, String>, String> {
    let mut options = BTreeMap::new();
    while let Some(option) = args.next() {
        if !allowed.contains(&option.as_str()) {
            return Err(usage());
        }
        let value = args
            .next()
            .ok_or_else(|| format!("valore mancante per {option}\n{}", usage()))?;
        if options.insert(option.clone(), value).is_some() {
            return Err(format!("opzione duplicata: {option}"));
        }
    }
    Ok(options)
}

fn required_option<'a>(
    options: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, String> {
    options.get(key).map(String::as_str).ok_or_else(usage)
}

fn write_new_file(path: &str, bytes: &[u8]) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error.to_string());
    }
    Ok(())
}

fn usage() -> String {
    "uso: loquere-cli id new --name <nome-dispositivo> --output <file>\n     loquere-cli id show --file <file>\n     loquere-cli invite create --file <file> --name <nome> [--expires-in 7d]\n     loquere-cli invite inspect <URI-o-codice-invito>\n     loquere-cli chat init --identity-file <file> --state-file <file>\n     loquere-cli chat show --identity-file <file> --state-file <file>\n     loquere-cli chat key-package --identity-file <file> --state-file <file> --output <file>\n     loquere-cli chat add-member --identity-file <file> --state-file <file> --key-package <file> --welcome-out <file> --tree-out <file> --commit-out <file>\n     loquere-cli chat join --identity-file <file> --state-file <file> --welcome <file> --tree <file>\n     loquere-cli chat apply-commit --identity-file <file> --state-file <file> --commit <file>\n     loquere-cli chat send --identity-file <file> --state-file <file> --message <testo> --output <file>\n     loquere-cli chat receive --identity-file <file> --state-file <file> --input <file>\n     loquere-cli --help".to_owned()
}

fn parse_duration(value: &str) -> Result<u64, String> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let amount: u64 = value[..split]
        .parse()
        .map_err(|_| format!("durata non valida: {value}"))?;
    let multiplier = match &value[split..] {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "w" => 7 * 24 * 60 * 60,
        _ => return Err(format!("unità durata non valida: {value}")),
    };
    amount
        .checked_mul(multiplier)
        .filter(|duration| *duration > 0)
        .ok_or_else(|| format!("durata fuori intervallo: {value}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unrecognized_commands_and_extra_arguments() {
        assert!(run(["send".to_owned()].into_iter()).is_err());
        assert!(run(["id".to_owned(), "new".to_owned(), "--name".to_owned()].into_iter()).is_err());
        assert!(
            run([
                "invite".to_owned(),
                "inspect".to_owned(),
                "bad".to_owned(),
                "extra".to_owned()
            ]
            .into_iter())
            .is_err()
        );
        assert!(run(["chat", "other"].map(str::to_owned).into_iter()).is_err());
        assert!(
            parse_chat_paths(
                [
                    "--identity-file",
                    "id",
                    "--state-file",
                    "state",
                    "--other",
                    "x"
                ]
                .map(str::to_owned)
                .into_iter()
            )
            .is_err()
        );
        assert!(
            parse_chat_options(
                ["--state-file", "one", "--state-file", "two"]
                    .map(str::to_owned)
                    .into_iter(),
                &["--state-file"]
            )
            .is_err()
        );
    }

    #[test]
    fn parses_expiration_duration_with_checked_units() {
        assert_eq!(parse_duration("7d"), Ok(604_800));
        assert_eq!(parse_duration("12h"), Ok(43_200));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("999999999999999999999w").is_err());
        assert!(parse_duration("5months").is_err());
    }
}
