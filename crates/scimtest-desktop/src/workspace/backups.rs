use std::io::Read;

use gpui::{Context, PathPromptOptions};
use scimtest_core::{Error, backup::StateBackup};

use super::{Editor, Workspace};

impl Workspace {
    pub(super) fn export_backup(&mut self, cx: &mut Context<Self>) {
        let Some(directory) = self.directory() else {
            return;
        };
        let environment = directory.environment.id.clone();
        let filename = format!("{}-backup.json", directory.environment.slug);
        let directory = dirs::document_dir().unwrap_or_else(std::env::temp_dir);
        let selected = cx.prompt_for_new_path(&directory, Some(&filename));
        cx.spawn(async move |view, cx| {
            let result = selected.await;
            let _ = view.update(cx, |view, cx| match result {
                Ok(Ok(Some(path))) => view.command(
                    move |store| {
                        store.write_backup(&environment, &path)?;
                        Ok((format!("Backup saved to {}", path.display()), None))
                    },
                    cx,
                ),
                Ok(Ok(None)) => {}
                error => {
                    view.message = format!("Could not open the save dialog: {error:?}");
                    view.failed = true;
                    cx.notify();
                }
            });
        })
        .detach();
    }

    pub(super) fn import_backup(&mut self, cx: &mut Context<Self>) {
        let selected = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Choose an environment backup".into()),
        });
        cx.spawn(async move |view, cx| {
            let path = match selected.await {
                Ok(Ok(Some(paths))) if !paths.is_empty() => paths[0].clone(),
                Ok(Ok(_)) => return,
                error => {
                    let _ = view.update(cx, |view, cx| {
                        view.message = format!("Could not open the file dialog: {error:?}");
                        view.failed = true;
                        cx.notify();
                    });
                    return;
                }
            };
            let read = cx
                .background_executor()
                .spawn(async move {
                    let mut data = Vec::new();
                    std::fs::File::open(path)?
                        .take((25 << 20) + 1)
                        .read_to_end(&mut data)?;
                    if data.len() > 25 << 20 {
                        return Err(Error::Validation("Backup is larger than 25 MiB".into()));
                    }
                    Ok::<StateBackup, Error>(serde_json::from_slice(&data)?)
                })
                .await;
            let _ = view.update(cx, |view, cx| {
                match read {
                    Ok(backup)
                        if Some(&backup.state.environment.id) == view.selected.as_ref()
                            && backup.version == 1 =>
                    {
                        view.editor = Some(Editor::RestoreBackup {
                            backup: Box::new(backup),
                        });
                        view.message.clear();
                    }
                    Ok(_) => {
                        view.message =
                            "Choose a version 1 backup for the selected environment".into();
                        view.failed = true;
                    }
                    Err(error) => {
                        view.message = error.to_string();
                        view.failed = true;
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }
}
