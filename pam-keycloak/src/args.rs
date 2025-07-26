#[derive(clap::Parser, Debug)]
pub struct Args {
    /// OIDC Token URL
    #[arg(long)]
    pub token_url: String,

    /// OIDC User Information URL
    #[arg(long)]
    pub userinfo_url: String,

    /// OIDC Client ID
    #[arg(long)]
    pub client_id: String,

    /// OIDC Client Secret
    #[arg(long)]
    pub client_secret: String,

    /// OIDC requested scopes
    #[arg(long, default_value = "openid profile email")]
    pub scope: String,

    /// PAM-compliant arguments to accept either `debug` or `use_first_pass`
    #[arg(index = 1)]
    _args: Vec<String>,
}
