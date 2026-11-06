use clap::Parser;
use std::{ffi::OsString, path::PathBuf};

#[derive(Clone, Debug, Default, Parser)]
#[command(name = "scimtest", version = version(), about = "scimtest identity test environment", args_override_self = true,
    after_help = "Environment:\n  SCIMTEST_STATE_FILE       SQLite state file\n  SCIMTEST_RUST_STATE_FILE  Rust preview state-file alias\n  SCIMTEST_PORT             Require this admin port\n  PORT                     Deprecated port alias")]
pub struct Options {
    /// SQLite state file. Defaults to a separate Rust preview directory.
    #[arg(long)]
    pub state_file: Option<PathBuf>,
    /// Require this loopback API port; otherwise prefer the last port or 8080.
    #[arg(long, default_value = "", hide_default_value = true, value_parser = parse_port)]
    pub port: u16,
    /// Print OIDC and SAML traffic to stdout.
    #[arg(long, action=clap::ArgAction::Set, num_args=0..=1, require_equals=true, default_missing_value="true", default_value_t=false)]
    pub debug: bool,
    /// Include credentials and tokens in debug output; also enables --debug.
    #[arg(long, action=clap::ArgAction::Set, num_args=0..=1, require_equals=true, default_missing_value="true", default_value_t=false)]
    pub debug_secrets: bool,
    /// Suppress opening the app when handing off to an existing instance.
    #[arg(long, action=clap::ArgAction::Set, num_args=0..=1, require_equals=true, default_missing_value="true", default_value_t=false)]
    pub no_open: bool,
}
impl Options {
    pub fn parse_cli() -> Self {
        Self::parse_from(arguments(std::env::args_os().collect()))
    }
    pub(super) fn state_path(&self) -> anyhow::Result<PathBuf> {
        let selected = self
            .state_file
            .clone()
            .filter(|path| !path.as_os_str().is_empty())
            .or_else(|| {
                std::env::var_os("SCIMTEST_STATE_FILE")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
            })
            .or_else(|| {
                std::env::var_os("SCIMTEST_RUST_STATE_FILE")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
            });
        super::canonical_state_path(&selected.map_or_else(super::default_state_path, Ok)?)
    }
}
pub fn version() -> &'static str {
    option_env!("SCIMTEST_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}
fn arguments(mut arguments: Vec<OsString>) -> Vec<OsString> {
    if let Some(command) = arguments.get(1).and_then(|value| value.to_str()) {
        match command {
            "web" => {
                arguments.remove(1);
            }
            "help" => arguments[1] = "--help".into(),
            "version" => arguments[1] = "--version".into(),
            _ => {}
        }
    }
    for argument in arguments.iter_mut().skip(1) {
        if let Some(value) = argument.to_str().and_then(|value| value.strip_prefix('-'))
            && matches!(
                value.split('=').next(),
                Some(
                    "port"
                        | "state-file"
                        | "debug"
                        | "debug-secrets"
                        | "no-open"
                        | "version"
                        | "help"
                )
            )
        {
            *argument = format!("--{value}").into();
        }
    }
    arguments
}
pub(super) fn parse_port(value: &str) -> Result<u16, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    trimmed
        .parse::<u16>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| format!("invalid port {value:?}: must be an integer from 1 through 65535"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_accepts_go_flags_subcommands_and_boolean_forms() {
        let parsed = Options::try_parse_from(arguments(
            [
                "scimtest",
                "web",
                "-port",
                " 9001 ",
                "-debug=false",
                "--debug-secrets",
                "--no-open",
                "--state-file",
                "/tmp/greendale/state.db",
            ]
            .map(OsString::from)
            .to_vec(),
        ))
        .unwrap();
        assert_eq!(parsed.port, 9001);
        assert!(!parsed.debug);
        assert!(parsed.debug_secrets);
        assert!(parsed.no_open);
        assert_eq!(
            parsed.state_file,
            Some(PathBuf::from("/tmp/greendale/state.db"))
        );
        assert_eq!(Options::try_parse_from(["scimtest"]).unwrap().port, 0);
        assert_eq!(
            Options::try_parse_from(["scimtest", "--port", "9001", "--port", "9002"])
                .unwrap()
                .port,
            9002
        );
        for value in ["0", "65536", "-1", "eight"] {
            assert!(
                Options::try_parse_from(["scimtest", "--port", value]).is_err(),
                "{value}"
            );
        }
        for (command, kind) in [
            ("help", clap::error::ErrorKind::DisplayHelp),
            ("version", clap::error::ErrorKind::DisplayVersion),
        ] {
            assert_eq!(
                Options::try_parse_from(arguments(
                    ["scimtest", command].map(OsString::from).to_vec()
                ))
                .unwrap_err()
                .kind(),
                kind
            );
        }
    }
}
