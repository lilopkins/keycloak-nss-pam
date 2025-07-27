use std::{
    borrow::Cow,
    collections::HashMap,
    fs,
    os::unix::{self, fs::PermissionsExt},
    path::PathBuf,
};

use common::{config, token::TokenResponse};
use copy_dir::copy_dir;
use pamsm::{LogLvl, PamError, PamLibExt, PamMsgStyle, PamServiceModule, pam_module};
use reqwest::blocking::Client;

mod api_types;
use api_types::UserInfoResponse;
use walkdir::WalkDir;

const DATA_UUID: &str = "keycloak-uuid";
const ENV_UID: &str = "KEYCLOAK_UID";
const ENV_GID: &str = "KEYCLOAK_GID";
const ENV_HOME: &str = "KEYCLOAK_HOME";

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
        if let Ok(Some(uid)) = pamh.getenv(ENV_UID) {
            let uid = uid.to_string_lossy().parse::<libc::uid_t>().unwrap();
            let gid = pamh
                .getenv(ENV_GID)
                .unwrap()
                .unwrap()
                .to_string_lossy()
                .parse::<libc::uid_t>()
                .unwrap();

            // If we're non-root and the home dir doesn't exist, let's try to do what we can.
            let home_dir = pamh
                .getenv(ENV_HOME)
                .map(|v| v.map(|v| v.to_string_lossy()));
            match home_dir {
                Err(_) | Ok(None) => return PamError::AUTHINFO_UNAVAIL,
                _ => (),
            }
            let home_dir = PathBuf::from(home_dir.unwrap().unwrap().into_owned());
            if !fs::exists(&home_dir).unwrap() {
                let _ = pamh.syslog(
                    LogLvl::INFO,
                    &format!("Creating home directory at {home_dir:?} for {uid}:{gid}"),
                );

                if let Err(e) = copy_dir("/etc/skel", &home_dir) {
                    let _ = pamh.syslog(LogLvl::ERR, &format!("Fail to copy skeleton: {e}"));
                    return PamError::SESSION_ERR;
                }

                for entry in WalkDir::new(&home_dir).into_iter().filter_map(|e| e.ok()) {
                    if let Err(e) = unix::fs::chown(entry.path(), Some(uid), Some(gid)) {
                        let _ = pamh.syslog(
                            LogLvl::WARNING,
                            &format!("Failed to set owner on {}: {e}", entry.path().display()),
                        );
                    }
                    if let Err(e) = fs::set_permissions(
                        entry.path(),
                        fs::Permissions::from_mode(if entry.path().is_dir() {
                            0o700
                        } else {
                            0o600
                        }),
                    ) {
                        let _ = pamh.syslog(
                            LogLvl::WARNING,
                            &format!(
                                "Failed to set permissions on {}: {e}",
                                entry.path().display()
                            ),
                        );
                    }
                }
            }
        }

        // Not for us!
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

    // Check if user exists and return early if not.
    let mut query = HashMap::new();
    query.insert("exact", Cow::Borrowed("true"));
    query.insert("username", username.clone());
    let users = common::api::get_users(&config, query, |v| {
        let _ = pamh.syslog(LogLvl::DEBUG, &v);
    })
    .map_err(|_| PamError::AUTHINFO_UNAVAIL)?;
    if users.len() != 1 {
        return Ok(PamError::USER_UNKNOWN);
    }

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
    form_data.insert("username", username.clone());
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
            let _ = pamh.putenv(&format!("{ENV_UID}={}", res.uid));
            let _ = pamh.putenv(&format!("{ENV_GID}={}", config.group_id));
            let _ = pamh.putenv(&format!(
                "{ENV_HOME}={}",
                config
                    .home_directory_parent
                    .join(PathBuf::from(username.into_owned()))
                    .to_str()
                    .unwrap()
            ));
        }
    }

    Ok(PamError::SUCCESS)
}

pam_module!(PamKeycloak);
