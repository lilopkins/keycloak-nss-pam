use std::{fs, os::unix::fs::PermissionsExt};

use libnss::passwd::Passwd;
use serde::{Deserialize, Serialize};

const CACHE_PATH: &str = "/var/cache/auth_keycloak.toml";

#[derive(Serialize, Deserialize, Default)]
pub struct Cache {
    pub user: Vec<User>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub uid: libc::uid_t,
    pub username: String,
    pub name: String,
    pub gid: libc::uid_t,
    pub home_dir: String,
    pub shell: String,
}

impl From<&Passwd> for User {
    fn from(passwd: &Passwd) -> Self {
        User {
            uid: passwd.uid,
            username: passwd.name.clone(),
            gid: passwd.gid,
            home_dir: passwd.dir.clone(),
            name: passwd.gecos.clone(),
            shell: passwd.shell.clone(),
        }
    }
}

impl From<User> for Passwd {
    fn from(value: User) -> Self {
        Passwd {
            uid: value.uid,
            gecos: value.name.clone(),
            name: value.username.clone(),
            gid: value.gid,
            passwd: "x".to_string(),
            dir: value.home_dir.clone(),
            shell: value.shell.clone(),
        }
    }
}

pub fn cache() -> Option<Cache> {
    if let Ok(data) = fs::read_to_string(CACHE_PATH) {
        toml::from_str(&data).ok()
    } else {
        None
    }
}

pub fn update_cache(users: &[User]) {
    let mut cache = cache().unwrap_or_default();
    for user in users {
        // Remove this UID
        let mut new_users = cache
            .user
            .into_iter()
            .filter(|u| u.uid != user.uid)
            .collect::<Vec<_>>();

        // Add this user back
        new_users.push(user.clone());

        // Continue
        cache.user = new_users;
    }
    let toml = toml::to_string_pretty(&cache).unwrap();
    let _ = fs::write(CACHE_PATH, toml);
    let _ = fs::set_permissions(CACHE_PATH, fs::Permissions::from_mode(0o644));
}
