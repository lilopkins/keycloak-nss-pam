use serde::Deserialize;

#[derive(Deserialize)]
#[serde(untagged)]
pub enum TokenResponse {
    Success {
        access_token: String,
        #[serde(rename = "expires_in")]
        _expires_in: usize,
        #[serde(rename = "refresh_token")]
        _refresh_token: Option<String>,
        #[serde(rename = "scope")]
        _scope: String,
    },
    Failure {
        error: String,
        error_description: Option<String>,
    },
}

#[derive(Deserialize, Debug)]
pub struct UserInfoResponse {
    pub sub: String,
    pub uid: String,

    #[serde(rename = "email_verified")]
    _email_verified: Option<bool>,

    #[serde(rename = "name")]
    _name: Option<String>,

    #[serde(rename = "preferred_username")]
    _preferred_username: Option<String>,

    #[serde(rename = "locale")]
    _locale: Option<String>,

    #[serde(rename = "given_name")]
    _given_name: Option<String>,

    #[serde(rename = "family_name")]
    _family_name: Option<String>,

    #[serde(rename = "email")]
    _email: Option<String>,
}
