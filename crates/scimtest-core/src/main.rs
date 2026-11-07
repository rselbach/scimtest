use anyhow::Result;
use scimtest_core::runtime::{Launch, Options, Runtime};

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::parse_cli();
    let no_open = options.no_open;
    let service = match Runtime::launch(options, &tokio::runtime::Handle::current()).await? {
        Launch::Started(service) => *service,
        Launch::Existing(instance) => {
            eprintln!("scimtest is already running at {}", instance.url);
            if !no_open {
                instance.open().await?;
            }
            return Ok(());
        }
    };
    eprintln!("scimtest Rust API: {}", service.url);
    eprintln!("Preview state: {}", service.state_file.display());
    service.run_until_signal().await
}
