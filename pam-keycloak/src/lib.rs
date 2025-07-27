use std::{borrow::Cow, collections::HashMap, fs, os::unix, process::Command};

use copy_dir::copy_dir;
use pamsm::{LogLvl, PamError, PamLibExt, PamMsgStyle, PamServiceModule, pam_module};
use reqwest::blocking::Client;

mod api_types;
use api_types::{TokenResponse, UserInfoResponse};
use walkdir::WalkDir;

const DATA_UUID: &str = "keycloak-uuid";
const DATA_UID: &str = "keycloak-uid";

struct PamKeycloak;

impl PamServiceModule for PamKeycloak {
    fn authenticate(
        pamh: pamsm::Pam,
        flags: pamsm::PamFlags,
        args: Vec<String>,
    ) -> pamsm::PamError {
        match authenticate(pamh, flags, args) {
            Ok(r) | Err(r) => r,
        }
    }

    fn setcred(pamh: pamsm::Pam, _: pamsm::PamFlags, _: Vec<String>) -> PamError {
        match pamh.retrieve_bytes(DATA_UUID) {
            Ok(_uuid) => PamError::SUCCESS,
            Err(_) => PamError::USER_UNKNOWN,
        }
    }

    fn acct_mgmt(pamh: pamsm::Pam, _: pamsm::PamFlags, _: Vec<String>) -> PamError {
        match pamh.retrieve_bytes(DATA_UUID) {
            Ok(_uuid) => PamError::SUCCESS,
            Err(_) => PamError::USER_UNKNOWN,
        }
    }

    fn open_session(pamh: pamsm::Pam, _: pamsm::PamFlags, _: Vec<String>) -> PamError {
        if let Ok(uid) = pamh.retrieve_bytes(DATA_UID) {
            // Parse config
            config::create_if_not_exists().unwrap();
            let config = config::read().unwrap();

            let uid = String::from_utf8_lossy(&uid).parse::<u32>().unwrap();
            let passwd_output = Command::new("getent")
                .arg("passwd")
                .arg(uid.to_string())
                .output()
                .unwrap();

            let passwd_output = String::from_utf8_lossy(&passwd_output.stdout);
            let mut passwd_entries = passwd_output.split(':');
            let home_dir = passwd_entries.nth(6).unwrap();

            // Create home directory if needed
            if !fs::exists(home_dir).unwrap() {
                fs::create_dir_all(home_dir).unwrap();
                copy_dir("/etc/skel", home_dir).unwrap();
                // Set permissions
                unix::fs::chown(home_dir, Some(uid), Some(config.group_id)).unwrap();
                for entry in WalkDir::new(home_dir).into_iter().filter_map(|e| e.ok()) {
                    unix::fs::chown(entry.path(), Some(uid), Some(config.group_id)).unwrap();
                }
            }
        }

        PamError::SUCCESS
    }

    fn close_session(_: pamsm::Pam, _: pamsm::PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

fn authenticate(
    pamh: pamsm::Pam,
    _flags: pamsm::PamFlags,
    _args: Vec<String>,
) -> Result<PamError, PamError> {
    // Parse config
    config::create_if_not_exists().unwrap();
    let config = config::read().unwrap();

    // Read or prompt for username
    let username = pamh.get_user(None)?.ok_or(PamError::AUTHINFO_UNAVAIL)?;
    let username = username.to_string_lossy();

    // Read or prompt for password
    let password = pamh.get_authtok(None)?.ok_or(PamError::AUTHINFO_UNAVAIL)?;
    let password = password.to_string_lossy();

    // Prompt for TOTP
    let totp = pamh
        .conv(Some("Multi-factor code: "), PamMsgStyle::PROMPT_ECHO_ON)?
        .ok_or(PamError::AUTHINFO_UNAVAIL)?;
    let totp = totp.to_string_lossy();

    let _ = pamh.syslog(LogLvl::DEBUG, "Sending authentication request");

    // Send direct grant request
    let mut form_data = HashMap::new();
    form_data.insert("username", username);
    form_data.insert("password", password);
    form_data.insert("totp", totp);
    form_data.insert("grant_type", Cow::Borrowed("password"));
    form_data.insert("scope", Cow::Owned(config.scopes));

    let client = Client::new();
    let res = client
        .post(config.token_url)
        .basic_auth(config.client_id, Some(config.client_secret))
        .form(&form_data)
        .send()
        .map_err(|e| {
            let _ = pamh.syslog(
                LogLvl::CRIT,
                "Failed to send request to OIDC token endpoint!",
            );
            let _ = pamh.syslog(LogLvl::CRIT, e.to_string().as_str());
            PamError::AUTHINFO_UNAVAIL
        })?
        .json::<TokenResponse>()
        .map_err(|e| {
            let _ = pamh.syslog(
                LogLvl::CRIT,
                "Failed to parse response from OIDC token endpoint!",
            );
            let _ = pamh.syslog(LogLvl::CRIT, e.to_string().as_str());
            PamError::AUTHINFO_UNAVAIL
        })?;

    match res {
        TokenResponse::Failure {
            error,
            error_description,
        } => {
            let _ = pamh.syslog(
                LogLvl::CRIT,
                &format!(
                    "Denied user because {error}{}",
                    error_description
                        .map(|s| format!(": {s}"))
                        .unwrap_or(String::new())
                ),
            );
            return Err(PamError::USER_UNKNOWN);
        }
        TokenResponse::Success { access_token, .. } => {
            let res = client
                .post(config.userinfo_url)
                .bearer_auth(access_token)
                .send()
                .map_err(|e| {
                    let _ = pamh.syslog(
                        LogLvl::CRIT,
                        "Failed to send request to OIDC userinfo endpoint!",
                    );
                    let _ = pamh.syslog(LogLvl::CRIT, e.to_string().as_str());
                    PamError::AUTH_ERR
                })?
                .json::<UserInfoResponse>()
                .map_err(|e| {
                    let _ = pamh.syslog(
                        LogLvl::CRIT,
                        "Failed to parse response from OIDC userinfo endpoint!",
                    );
                    let _ = pamh.syslog(LogLvl::CRIT, e.to_string().as_str());
                    PamError::AUTH_ERR
                })?;
            let _ = pamh.syslog(LogLvl::DEBUG, &format!("User is {res:?}"));
            let _ = pamh.send_bytes(DATA_UUID, res.sub.into_bytes(), None);
            let _ = pamh.send_bytes(DATA_UID, res.uid.into_bytes(), None);
        }
    }

    Ok(PamError::SUCCESS)
}

pam_module!(PamKeycloak);
