use std::path::PathBuf;

use rune::{FileDialogOptions, Tx};
use scimtest_core::Error;

use super::Workspace;

/// A file that tells the app under test how to reach an environment's identity provider.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Export {
    /// The connection config JSON, with the OIDC and SAML endpoints and credentials.
    Config,
    /// The SAML identity provider metadata XML.
    Metadata,
    /// The active SAML signing certificate, in PEM.
    Certificate,
}

impl Export {
    fn noun(self) -> &'static str {
        match self {
            Export::Config => "Config JSON",
            Export::Metadata => "SAML metadata",
            Export::Certificate => "Certificate",
        }
    }
}

impl Workspace {
    /// Copies an environment's `export`, or with `save` writes it to a file the user picks.
    pub(super) fn export_connection(
        &mut self,
        environment: String,
        export: Export,
        save: bool,
        tx: &mut Tx,
    ) {
        if self.busy {
            return;
        }
        let Some(directory) = self
            .directories
            .iter()
            .find(|directory| directory.environment.id == environment)
        else {
            return;
        };
        let slug = &directory.environment.slug;
        let (file_name, filter, extension) = match export {
            Export::Config => (format!("{slug}-config.json"), "JSON", "json"),
            Export::Metadata => (format!("{slug}-idp-metadata.xml"), "XML", "xml"),
            Export::Certificate => (format!("{slug}-idp-certificate.pem"), "PEM", "pem"),
        };
        self.busy = true;
        self.message.clear();
        self.failed = false;
        if !save {
            self.write_connection(environment, export, None);
            return;
        }
        let options = FileDialogOptions {
            title: format!("Save {}", export.noun()),
            directory: Some(dirs::document_dir().unwrap_or_else(std::env::temp_dir)),
            file_name: Some(file_name),
            ..Default::default()
        }
        .filter(filter, &[extension]);
        tx.save_file(options, move |s: &mut Workspace, result, _| match result {
            Ok(Some(path)) => s.write_connection(environment, export, Some(path)),
            Ok(None) => s.busy = false,
            Err(error) => {
                s.busy = false;
                s.fail(format!("Could not open the save dialog: {error}"));
            }
        });
    }

    /// Writes `export` to `path`, or copies it without one.
    fn write_connection(&self, environment: String, export: Export, path: Option<PathBuf>) {
        let store = self.store.clone();
        let tunnel = self.tunnel_service.clone();
        let local_base = self.api_url.clone();
        let work = self.executor.spawn_blocking(move || {
            let base = tunnel.effective_base(&local_base)?;
            let noun = export.noun();
            let contents = match (export, &path) {
                // The config can hold the client secret, so it is written privately.
                (Export::Config, Some(path)) => {
                    store.write_connection_config(&environment, &base, path)?;
                    return Ok::<_, Error>((None, format!("Config saved to {}", path.display())));
                }
                (Export::Config, None) => {
                    serde_json::to_string_pretty(&store.connection_config(&environment, &base)?)?
                }
                (Export::Metadata, _) => scimtest_core::saml::metadata(
                    &store,
                    &store.directory(&environment)?.environment,
                    &base,
                )?,
                (Export::Certificate, _) => {
                    store
                        .active_signing_key(&environment)?
                        .stored
                        .certificate_pem
                }
            };
            match path {
                Some(path) => {
                    std::fs::write(&path, contents)?;
                    Ok((None, format!("{noun} saved to {}", path.display())))
                }
                None => Ok((Some(contents), format!("{noun} copied"))),
            }
        });
        self.task(work, |s, result, tx| {
            s.busy = false;
            match result {
                Ok(Ok((contents, message))) => {
                    if let Some(contents) = contents {
                        tx.copy(contents);
                    }
                    s.message = message;
                    s.failed = false;
                }
                Ok(Err(error)) => s.fail(error.to_string()),
                Err(error) => s.fail(error.to_string()),
            }
        });
    }
}
