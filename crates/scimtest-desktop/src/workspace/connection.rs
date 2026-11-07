use super::Workspace;
use gpui::{ClipboardItem, Context};
use scimtest_core::Error;

impl Workspace {
    pub(super) fn export_connection(
        &mut self,
        environment: String,
        save: bool,
        cx: &mut Context<Self>,
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
        let filename = format!("{}-config.json", directory.environment.slug);
        let directory = dirs::document_dir().unwrap_or_else(std::env::temp_dir);
        let prompt = save.then(|| cx.prompt_for_new_path(&directory, Some(&filename)));
        let store = self.store.clone();
        let tunnel = self.tunnel_service.clone();
        let local_base = self.api_url.clone();
        self.busy = true;
        self.message.clear();
        self.failed = false;
        cx.spawn(async move |view, cx| {
            let path = match prompt {
                Some(prompt) => match prompt.await {
                    Ok(Ok(Some(path))) => Some(path),
                    result => {
                        let _ = view.update(cx, |view, cx| {
                            view.busy = false;
                            if !matches!(result, Ok(Ok(None))) {
                                view.message =
                                    format!("Could not open the save dialog: {result:?}");
                                view.failed = true;
                            }
                            cx.notify();
                        });
                        return;
                    }
                },
                None => None,
            };
            let result = cx
                .background_executor()
                .spawn(async move {
                    let base = tunnel.effective_base(&local_base)?;
                    if let Some(path) = path {
                        store.write_connection_config(&environment, &base, &path)?;
                        return Ok::<_, Error>((
                            None,
                            format!("Config saved to {}", path.display()),
                        ));
                    }
                    let json = serde_json::to_string_pretty(
                        &store.connection_config(&environment, &base)?,
                    )?;
                    Ok((Some(json), "Config JSON copied".into()))
                })
                .await;
            let _ = view.update(cx, |view, cx| {
                view.busy = false;
                match result {
                    Ok((json, message)) => {
                        if let Some(json) = json {
                            cx.write_to_clipboard(ClipboardItem::new_string(json));
                        }
                        view.message = message;
                        view.failed = false;
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
        cx.notify();
    }
}
