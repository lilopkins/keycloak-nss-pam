use std::{fs, io, os::unix::fs::PermissionsExt, path::PathBuf};

use serde::{Deserialize, Serialize};

pub const CONFIG_PATH: &str = "/etc/auth_keycloak.toml";

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub token_url: String,
    pub userinfo_url: String,
    pub api_url: String,
    pub realm: String,
    pub uid_attribute_id: String,
    pub uid_token_claim: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: String,
    pub start_uid: libc::uid_t,
    pub group_id: libc::uid_t,
    pub home_directory_parent: PathBuf,
    pub shell: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            token_url: "https://example.com/realms/master/protocol/openid-connect/token"
                .to_string(),
            userinfo_url: "https://example.com/realms/master/protocol/openid-connect/userinfo"
                .to_string(),
            api_url: "https://example.com/admin".to_string(),
            realm: "master".to_string(),
            uid_attribute_id: "linux_uid".to_string(),
            uid_token_claim: "uid".to_string(),
            client_id: String::default(),
            client_secret: String::default(),
            scopes: "openid profile email uid".to_string(),
            start_uid: 1000,
            group_id: 1000,
            home_directory_parent: PathBuf::from("/home"),
            shell: "/bin/bash".to_string(),
        }
    }
}

pub fn create_if_not_exists() -> Result<(), io::Error> {
    if !fs::exists(CONFIG_PATH)? {
        fs::write(
            CONFIG_PATH,
            toml::to_string_pretty(&Config::default()).unwrap(),
        )?;
        fs::set_permissions(CONFIG_PATH, fs::Permissions::from_mode(0o0600))?;
    }

    Ok(())
}

pub fn read() -> Result<Config, io::Error> {
    fs::set_permissions(CONFIG_PATH, fs::Permissions::from_mode(0o0600))?;
    toml::from_str(&fs::read_to_string(CONFIG_PATH)?)
        .map_err(|_| io::Error::other("failed to deserialize"))
}
