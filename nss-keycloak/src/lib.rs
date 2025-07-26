use std::{borrow::Cow, collections::HashMap, ffi::CString, panic};

use libnss::{interop::Response, libnss_passwd_hooks, passwd::PasswdHooks};
use reqwest::blocking::Client;

use crate::{api_types::UserRepresentation, config::Config};

mod api_types;
mod config;
mod token;
mod uid;

struct KeycloakPasswd;
libnss_passwd_hooks!(keycloak, KeycloakPasswd);

impl PasswdHooks for KeycloakPasswd {
    fn get_all_entries() -> Response<Vec<libnss::passwd::Passwd>> {
        openlog();
        log(libc::LOG_DEBUG, "get_all_entries");

        if config::create_if_not_exists().is_err() {
            log(
                libc::LOG_WARNING,
                format!(
                    "Default config created, update it at {}",
                    config::CONFIG_PATH
                ),
            );
            return Response::TryAgain;
        }

        let config = config::read();
        if config.is_err() {
            log(libc::LOG_WARNING, "Failed to read config!");
            return Response::TryAgain;
        }
        // SAFETY: just validated
        let config = config.unwrap();

        let mut query = HashMap::new();
        query.insert("max", "9999");

        let res = get_users(&config, query);
        if let Err(e) = res {
            log(libc::LOG_ERR, format!("Failed to get user: {e}"));
            return Response::TryAgain;
        }
        let res = res.unwrap();
        // SAFETY: just validated
        Response::Success(
            res.iter()
                .filter(|ur| ur.attributes.contains_key(&config.uid_attribute_id))
                .map(|ur| {
                    ur.to_passwd(
                        &config,
                        ur.attributes
                            .get(&config.uid_attribute_id)
                            .unwrap()
                            .first()
                            .unwrap()
                            .parse::<libc::uid_t>()
                            .unwrap(),
                    )
                })
                .collect(),
        )
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<libnss::passwd::Passwd> {
        openlog();
        log(libc::LOG_DEBUG, "get_entry_by_uid");

        if config::create_if_not_exists().is_err() {
            log(
                libc::LOG_WARNING,
                format!(
                    "Default config created, update it at {}",
                    config::CONFIG_PATH
                ),
            );
            return Response::TryAgain;
        }

        let config = config::read();
        if config.is_err() {
            log(libc::LOG_WARNING, "Failed to read config!");
            return Response::TryAgain;
        }
        // SAFETY: just validated
        let config = config.unwrap();

        let mut query = HashMap::new();
        query.insert("q", format!("{}:{uid}", config.uid_attribute_id));

        let res = get_users(&config, query);
        if let Err(e) = res {
            log(libc::LOG_ERR, format!("Failed to get user: {e}"));
            return Response::TryAgain;
        }
        let res = res.unwrap();
        if res.len() != 1 {
            return Response::NotFound;
        }

        // SAFETY: checked above
        let user = res.first().unwrap();
        log(libc::LOG_DEBUG, format!("{user:?}"));

        Response::Success(user.to_passwd(&config, uid))
    }

    fn get_entry_by_name(name: String) -> Response<libnss::passwd::Passwd> {
        openlog();
        log(libc::LOG_DEBUG, "get_entry_by_name");

        if config::create_if_not_exists().is_err() {
            log(
                libc::LOG_WARNING,
                format!(
                    "Default config created, update it at {}",
                    config::CONFIG_PATH
                ),
            );
            return Response::TryAgain;
        }

        let config = config::read();
        if config.is_err() {
            log(libc::LOG_WARNING, "Failed to read config!");
            return Response::TryAgain;
        }
        // SAFETY: just validated
        let config = config.unwrap();

        let mut query = HashMap::new();
        query.insert("exact", Cow::Borrowed("true"));
        query.insert("username", Cow::Owned(name));

        let res = get_users(&config, query);
        if let Err(e) = res {
            log(libc::LOG_ERR, format!("Failed to get user: {e}"));
            return Response::TryAgain;
        }
        let res = res.unwrap();

        if res.len() != 1 {
            return Response::NotFound;
        }

        // SAFETY: checked above
        let user = res.first().unwrap();
        log(libc::LOG_DEBUG, format!("{user:?}"));

        let uid = if user.attributes.contains_key(&config.uid_attribute_id) {
            // Get from attribute
            // SAFETY: checked in if
            let uids = user.attributes.get(&config.uid_attribute_id).unwrap();
            // SAFETY: guaranteed single value by Keycloak
            let uid = uids.first().unwrap().parse::<libc::uid_t>().unwrap();
            log(libc::LOG_DEBUG, format!("User UID known: {uid}"));
            uid
        } else {
            let new_uid = uid::get_first_available_uid(config.start_uid);
            log(libc::LOG_DEBUG, format!("New UID determined: {new_uid}"));

            // Update user's UID
            let token = token::get_client_access_token(
                &config.token_url,
                &config.client_id,
                &config.client_secret,
            )
            .ok_or("");
            if let Err(e) = token {
                log(libc::LOG_ERR, format!("Failed to get token: {e}"));
                return Response::TryAgain;
            }
            let token = token.unwrap();

            let client = Client::new();
            let mut update = user.clone();
            update
                .attributes
                .insert(config.uid_attribute_id.clone(), vec![new_uid.to_string()]);

            let req = client
                .put(format!(
                    "{}/realms/{}/users/{}",
                    &config.api_url, &config.realm, user.id
                ))
                .bearer_auth(token)
                .body(serde_json::to_string(&update).unwrap());

            log(libc::LOG_DEBUG, format!("{req:?}"));

            let res = req.send().unwrap();

            if !res.status().is_success() {
                return Response::TryAgain;
            }

            new_uid
        };

        Response::Success(user.to_passwd(&config, uid))
    }
}

fn get_users<T>(
    config: &Config,
    query_parameters: HashMap<&str, T>,
) -> Result<Vec<UserRepresentation>, Box<dyn std::error::Error>>
where
    T: serde::Serialize + Sized,
{
    let token =
        token::get_client_access_token(&config.token_url, &config.client_id, &config.client_secret)
            .ok_or("")?;

    let client = Client::new();

    if cfg!(debug_assertions) {
        let res = client
            .get(format!("{}/realms/{}/users", config.api_url, config.realm))
            .bearer_auth(&token)
            .query(&query_parameters)
            .send()?;
        log(libc::LOG_DEBUG, res.text().unwrap());
    }

    let res = client
        .get(format!("{}/realms/{}/users", config.api_url, config.realm))
        .bearer_auth(token)
        .query(&query_parameters)
        .send()?;

    Ok(res.json::<Vec<UserRepresentation>>()?)
}

fn openlog() {
    panic::set_hook(Box::new(|p| {
        log(libc::LOG_CRIT, p.to_string());
    }));

    let str = Box::new(CString::new("nss-keycloak").unwrap());
    unsafe {
        libc::openlog(str.as_ptr(), 0, libc::LOG_AUTH);
    }
    std::mem::forget(str);
}

fn log<S: AsRef<str>>(priority: i32, message: S) {
    if priority == libc::LOG_DEBUG && !cfg!(debug_assertions) {
        return;
    }

    let message = CString::new(message.as_ref()).unwrap();
    unsafe {
        libc::syslog(priority, message.as_ptr());
    }
}
