use common::{api::types::UserRepresentation, config::Config};
use libnss::passwd::Passwd;

pub trait ToPasswd {
    fn to_passwd(&self, config: &Config, uid: libc::uid_t) -> Passwd;
}

impl ToPasswd for UserRepresentation {
    fn to_passwd(&self, config: &Config, uid: libc::uid_t) -> Passwd {
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
