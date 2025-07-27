use std::collections::HashMap;

use reqwest::blocking::Client;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(untagged)]
pub enum TokenResponse {
    Success {
        access_token: String,
        expires_in: usize,
        refresh_token: Option<String>,
        scope: String,
    },
    Failure {
        error: String,
        error_description: Option<String>,
    },
}

pub fn get_client_access_token(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
) -> Option<String> {
    let mut form_data = HashMap::new();
    form_data.insert("grant_type", "client_credentials");

    let client = Client::new();
    let res = client
        .post(token_url)
        .basic_auth(client_id, Some(client_secret))
        .form(&form_data)
        .send()
        .ok()?
        .json::<TokenResponse>()
        .ok()?;

    match res {
        TokenResponse::Success { access_token, .. } => Some(access_token),
        _ => None,
    }
}
