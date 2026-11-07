use serde::{Deserialize, Deserializer};

pub mod application;
mod auth;
pub mod config;
mod dashboard;
mod enrollment;
mod forwarding;
mod network;
mod registration;
mod replacement;
mod runtime;
mod server;
pub mod store;
mod tunnel;

pub use config::Config;
pub use server::Server;

fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn null_default<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
    deserializer: D,
) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}
