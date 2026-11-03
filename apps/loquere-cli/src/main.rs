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
    "uso: loquere-cli invite inspect <URI-o-codice-invito>\n     loquere-cli --help".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unrecognized_commands_and_extra_arguments() {
        assert!(run(["send".to_owned()].into_iter()).is_err());
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
