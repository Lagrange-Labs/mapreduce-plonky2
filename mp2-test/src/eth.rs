use std::env;

/// Get the Sepolia test URL.
pub fn get_sepolia_url() -> String {
    #[cfg(feature = "ci")]
    let url = env::var("CI_SEPOLIA").expect("CI_SEPOLIA env var not set");
    #[cfg(not(feature = "ci"))]
    let url =
        env::var("CI_SEPOLIA").unwrap_or("https://ethereum-sepolia-rpc.publicnode.com".to_string());
    url.to_string()
}

/// Get the Mainnet test URL.
pub fn get_mainnet_url() -> String {
    #[cfg(feature = "ci")]
    let url = env::var("CI_ETH").expect("CI_ETH env var not set");
    #[cfg(not(feature = "ci"))]
    let url = "https://eth.llamarpc.com";
    url.to_string()
}
