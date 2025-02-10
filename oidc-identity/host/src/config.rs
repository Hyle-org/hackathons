use config::{Config, Environment, File};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub fn load_config(config_file_path: Option<&Path>) -> anyhow::Result<AppConfig> {
    let mut settings = Config::builder();

    if let Some(path) = config_file_path {
        settings = settings.add_source(File::from(path).required(true));
    }

    let settings = settings
        .add_source(Environment::with_prefix("OIDC").separator("__"))
        .build()?;

    Ok(settings.try_deserialize::<AppConfig>()?)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    pub contract: ContractConfig,
    pub server: ServerConfig,
    pub identity_providers: HashMap<String, IdentityProvider>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractConfig {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub server_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityProvider {
    pub issuer_url: String,
    pub audience_url: String,
    pub jwk_public_key_url: String,
}

impl IdentityProvider {
    /// Fetch client secret from environment variables.
    pub fn get_client_secret(&self, provider_name: &str) -> String {
        std::env::var(format!(
            "OIDC_{}_CLIENT_SECRET",
            provider_name.to_uppercase()
        ))
        .unwrap_or_else(|_| {
            panic!(
                "Missing environment variable: OIDC_{}_CLIENT_SECRET",
                provider_name.to_uppercase()
            )
        })
    }
}
