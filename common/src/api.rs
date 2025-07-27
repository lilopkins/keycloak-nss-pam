use std::collections::HashMap;

use reqwest::blocking::Client;

use crate::{api::types::UserRepresentation, config::Config, token};

pub fn get_users<T, F>(
    config: &Config,
    query_parameters: HashMap<&str, T>,
    debug_log: F
) -> Result<Vec<UserRepresentation>, Box<dyn std::error::Error>>
where
    T: serde::Serialize + Sized,
    F: FnOnce(String),
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
        debug_log(res.text().unwrap());
    }

    let res = client
        .get(format!("{}/realms/{}/users", config.api_url, config.realm))
        .bearer_auth(token)
        .query(&query_parameters)
        .send()?;

    Ok(res.json::<Vec<UserRepresentation>>()?)
}

pub mod types {
    use std::collections::HashMap;

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
}
