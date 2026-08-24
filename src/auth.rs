//! Shared Auth consumer boundary.
//!
//! A desktop app is a public client. It may perform PKCE/provider exchange and
//! ordinary user-token verification through the official typed client, but it
//! must never receive the service credential for protected introspection.
//! Supabase is a credential authority; HHM product authorization remains in
//! the HHM backend.

#[cfg(feature = "shared-auth-client")]
pub use shared_auth_client::{ClientError, SharedAuthClient};

/// Creates the official redirect-free, bounded Shared Auth client.
///
/// The returned client intentionally has no introspection service credential.
/// Exact issuer, audience, authorized client, expiry, assurance, and route
/// permissions still have to be enforced by the authoritative backend/guard.
///
/// # Errors
///
/// Returns the upstream typed configuration error when the base URL is invalid
/// or is cleartext on a non-loopback host.
#[cfg(feature = "shared-auth-client")]
pub fn public_client(base_url: &str) -> Result<SharedAuthClient, ClientError> {
    SharedAuthClient::try_new(base_url)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "shared-auth-client")]
    use super::*;

    #[cfg(feature = "shared-auth-client")]
    #[test]
    fn rejects_invalid_or_remote_cleartext_authorities() {
        assert!(public_client("not a URL").is_err());
        assert!(public_client("http://auth.example.test").is_err());
        assert!(public_client("https://auth.example.test/shared-auth").is_ok());
    }
}
