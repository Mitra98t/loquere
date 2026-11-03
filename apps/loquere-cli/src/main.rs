use std::process::ExitCode;

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
        (Some("--help" | "-h"), _) | (None, _) => {
            println!("{}", usage());
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "uso: loquere-cli id new --name <nome-dispositivo> --output <file>\n     loquere-cli id show --file <file>\n     loquere-cli invite inspect <URI-o-codice-invito>\n     loquere-cli --help".to_owned()
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
    }
}
