use std::collections::HashMap;

use config::Config;
use libnss::passwd::Passwd;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UserRepresentation {
    pub id: String,
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub attributes: HashMap<String, Vec<String>>,

    #[serde(flatten)]
    pub _the_rest: HashMap<String, serde_json::Value>,
}

impl UserRepresentation {
    pub fn to_passwd(&self, config: &Config, uid: libc::uid_t) -> Passwd {
        Passwd {
            uid,
            gecos: format!("{} {}", self.first_name, self.last_name),
            name: self.username.clone(),
            gid: config.group_id,
            passwd: "x".to_string(),
            dir: config
                .home_directory_parent
                .clone()
                .join(self.username.clone())
                .to_string_lossy()
                .into_owned(),
            shell: config.shell.clone(),
        }
    }
}
