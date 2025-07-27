use std::{borrow::Cow, collections::HashMap, ffi::CString, panic};

use common::{api::get_users, config, token};
use libnss::{
    interop::Response,
    libnss_passwd_hooks,
    passwd::{Passwd, PasswdHooks},
};
use reqwest::blocking::Client;

mod cache;
mod to_passwd;
use to_passwd::ToPasswd;
mod uid;

struct KeycloakPasswd;
libnss_passwd_hooks!(keycloak, KeycloakPasswd);

impl PasswdHooks for KeycloakPasswd {
    fn get_all_entries() -> Response<Vec<libnss::passwd::Passwd>> {
        openlog();
        log(
            libc::LOG_DEBUG,
            format!("get_all_entries, v{}", env!("CARGO_PKG_VERSION")),
        );

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
            log(
                libc::LOG_WARNING,
                "Failed to read config (might be running as a user, in which case this is normal), trying cache!",
            );

            if let Some(cache) = cache::cache() {
                let passwds: Vec<Passwd> = cache.user.iter().map(|u| u.clone().into()).collect();
                return Response::Success(passwds);
            }

            return Response::TryAgain;
        }
        // SAFETY: just validated
        let config = config.unwrap();

        let mut query = HashMap::new();
        query.insert("max", "9999");

        let res = get_users(&config, query, |v| log(libc::LOG_DEBUG, v));
        if let Err(e) = res {
            log(libc::LOG_ERR, format!("Failed to get user: {e}"));
            return Response::TryAgain;
        }
        let res = res.unwrap();
        let passwds = res
            .iter()
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
            .collect::<Vec<_>>();

        cache::update_cache(&passwds.iter().map(Into::into).collect::<Vec<_>>());
        // SAFETY: just validated
        Response::Success(passwds)
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<libnss::passwd::Passwd> {
        openlog();
        log(
            libc::LOG_DEBUG,
            format!("get_entry_by_uid, v{}", env!("CARGO_PKG_VERSION")),
        );

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
            log(
                libc::LOG_WARNING,
                "Failed to read config (might be running as a user, in which case this is normal), trying cache!",
            );

            if let Some(cache) = cache::cache() {
                let passwds: Vec<Passwd> = cache.user.iter().map(|u| u.clone().into()).collect();
                if let Some(passwd) = passwds.iter().find(|p| p.uid == uid) {
                    return Response::Success(passwd.clone());
                }
            }
            return Response::TryAgain;
        }
        // SAFETY: just validated
        let config = config.unwrap();

        let mut query = HashMap::new();
        query.insert("q", format!("{}:{uid}", config.uid_attribute_id));

        let res = get_users(&config, query, |v| log(libc::LOG_DEBUG, v));
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

        let passwd = user.to_passwd(&config, uid);
        cache::update_cache(&[(&passwd).into()]);
        Response::Success(passwd)
    }

    fn get_entry_by_name(name: String) -> Response<libnss::passwd::Passwd> {
        openlog();
        log(
            libc::LOG_DEBUG,
            format!("get_entry_by_name, v{}", env!("CARGO_PKG_VERSION")),
        );

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
            log(
                libc::LOG_WARNING,
                "Failed to read config (might be running as a user, in which case this is normal), trying cache!",
            );

            if let Some(cache) = cache::cache() {
                let passwds: Vec<Passwd> = cache.user.iter().map(|u| u.clone().into()).collect();
                if let Some(passwd) = passwds.iter().find(|p| p.name == name) {
                    return Response::Success(passwd.clone());
                }
            }
            return Response::TryAgain;
        }
        // SAFETY: just validated
        let config = config.unwrap();

        let mut query = HashMap::new();
        query.insert("exact", Cow::Borrowed("true"));
        query.insert("username", Cow::Owned(name));

        let res = get_users(&config, query, |v| log(libc::LOG_DEBUG, v));
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

        let passwd = user.to_passwd(&config, uid);
        cache::update_cache(&[(&passwd).into()]);
        Response::Success(passwd)
    }
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
