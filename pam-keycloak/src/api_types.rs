use serde::Deserialize;

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
