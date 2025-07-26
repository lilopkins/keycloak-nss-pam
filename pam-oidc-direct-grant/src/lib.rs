use std::{borrow::Cow, collections::HashMap};

use clap::Parser;
use pamsm::{LogLvl, PamError, PamLibExt, PamMsgStyle, PamServiceModule, pam_module};
use reqwest::blocking::Client;

mod args;
use args::Args;

mod api_types;
use api_types::{TokenResponse, UserInfoResponse};

struct PamOidcDirectGrant;

impl PamServiceModule for PamOidcDirectGrant {
    fn authenticate(pamh: pamsm::Pam, flags: pamsm::PamFlags, args: Vec<String>) -> pamsm::PamError {
        match authenticate(pamh, flags, args) {
            Ok(r) | Err(r) => r,
        }
    }

    fn setcred(_: pamsm::Pam, _: pamsm::PamFlags, _: Vec<String>) -> PamError {
        PamError::CRED_UNAVAIL
    }

    fn acct_mgmt(_: pamsm::Pam, _: pamsm::PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn open_session(_: pamsm::Pam, _: pamsm::PamFlags, _: Vec<String>) -> PamError {
        // TODO Maybe create home directory here and set UID and group?
        PamError::SUCCESS
    }

    fn close_session(_: pamsm::Pam, _: pamsm::PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn chauthtok(pamh: pamsm::Pam, _: pamsm::PamFlags, _: Vec<String>) -> PamError {
        let _ = pamh.syslog(
            LogLvl::WARNING,
            "Changing OIDC passwords isn't possible via PAM",
        );
        PamError::AUTHTOK_ERR
    }
}

fn authenticate(
    pamh: pamsm::Pam,
    _flags: pamsm::PamFlags,
    mut args: Vec<String>,
) -> Result<PamError, PamError> {
    // Parse arguments
    let mut args_with_prefix = vec!["pam_oidc_direct_grant".to_owned()];
    args_with_prefix.append(&mut args);
    let args = Args::try_parse_from(args_with_prefix).map_err(|e| {
        let _ = pamh.syslog(
            LogLvl::CRIT,
            "The argument's couldn't be parsed for pam_oidc_direct_grant.so!",
        );
        let _ = pamh.syslog(LogLvl::CRIT, e.to_string().as_str());
        PamError::AUTH_ERR
    })?;

    // Read or prompt for username
    let username = pamh.get_user(None)?.ok_or(PamError::AUTHINFO_UNAVAIL)?;
    let username = username.to_string_lossy().to_owned();

    // Read or prompt for password
    let password = pamh.get_authtok(None)?.ok_or(PamError::AUTHINFO_UNAVAIL)?;
    let password = password.to_string_lossy().to_owned();

    // Prompt for TOTP
    let totp = pamh
        .conv(Some("Multi-factor code: "), PamMsgStyle::PROMPT_ECHO_ON)?
        .ok_or(PamError::AUTHINFO_UNAVAIL)?;
    let _ = pamh.syslog(
        LogLvl::CRIT,
        &format!("TOTP: {totp:?}"),
    );
    let totp = totp.to_string_lossy().to_owned();

    // Send direct grant request
    let mut form_data = HashMap::new();
    form_data.insert("username", username);
    form_data.insert("password", password);
    form_data.insert("totp", totp);
    form_data.insert("grant_type", Cow::Borrowed("password"));
    form_data.insert("scope", Cow::Owned(args.scope));
    let _ = pamh.syslog(
        LogLvl::CRIT,
        &format!("Data: {form_data:?}"),
    );

    let client = Client::new();
    let res = client
        .post(args.token_url)
        .basic_auth(args.client_id, Some(args.client_secret))
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
                .post(args.userinfo_url)
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
            let _ = pamh.syslog(
                LogLvl::INFO,
                &format!(
                    "User is {res:?}"
                ),
            );
        }
    }

    Ok(PamError::SUCCESS)
}

pam_module!(PamOidcDirectGrant);
