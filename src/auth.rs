//! Fail-closed configuration boundary for the official Shared Auth adapter.
//!
//! This public repository does not implement token parsing, JWT/JWKS
//! verification, provider exchange, introspection, or a production success
//! stub. Those operations remain unavailable until an official typed Shared
//! Auth client artifact is accessible to public builds. The eventual adapter
//! must consume the package declared in `.zpkg.toml` and preserve the reviewed
//! identity contract.

use std::{fmt, net::IpAddr};

use url::{Host, Url};

const MAX_PUBLIC_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedAuthPublicClientConfig {
    authority: Url,
    issuer: Url,
    audience: String,
    client_id: String,
}

impl SharedAuthPublicClientConfig {
    /// Validates non-secret configuration for a future official client.
    ///
    /// This function does not create an authentication client or make auth
    /// available. Remote authorities must use HTTPS; loopback HTTP is accepted
    /// for local development only. URL credentials, query strings, and
    /// fragments are rejected.
    ///
    /// # Errors
    ///
    /// Returns a bounded configuration error without reflecting the supplied
    /// URL or identifier.
    pub fn try_new(
        authority: &str,
        issuer: &str,
        audience: &str,
        client_id: &str,
    ) -> Result<Self, AuthConfigError> {
        let authority = validated_endpoint(authority, AuthConfigError::InvalidAuthority)?;
        let issuer = validated_endpoint(issuer, AuthConfigError::InvalidIssuer)?;
        if !valid_identifier(audience) {
            return Err(AuthConfigError::InvalidAudience);
        }
        if !valid_identifier(client_id) {
            return Err(AuthConfigError::InvalidClientId);
        }
        Ok(Self {
            authority,
            issuer,
            audience: audience.to_owned(),
            client_id: client_id.to_owned(),
        })
    }

    #[must_use]
    pub fn authority(&self) -> &Url {
        &self.authority
    }

    #[must_use]
    pub fn issuer(&self) -> &Url {
        &self.issuer
    }

    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthConfigError {
    InvalidAuthority,
    InvalidIssuer,
    InsecureRemoteAuthority,
    EmbeddedCredentials,
    QueryOrFragment,
    InvalidAudience,
    InvalidClientId,
}

impl fmt::Display for AuthConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAuthority => "invalid Shared Auth authority",
            Self::InvalidIssuer => "invalid Shared Auth issuer",
            Self::InsecureRemoteAuthority => "remote Shared Auth endpoints require HTTPS",
            Self::EmbeddedCredentials => "Shared Auth endpoint credentials are forbidden",
            Self::QueryOrFragment => "Shared Auth endpoints cannot contain a query or fragment",
            Self::InvalidAudience => "invalid Shared Auth audience",
            Self::InvalidClientId => "invalid Shared Auth public client identifier",
        })
    }
}

impl std::error::Error for AuthConfigError {}

fn validated_endpoint(input: &str, invalid: AuthConfigError) -> Result<Url, AuthConfigError> {
    let parsed = Url::parse(input).map_err(|_| invalid)?;
    if parsed.host().is_none() {
        return Err(invalid);
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AuthConfigError::EmbeddedCredentials);
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(AuthConfigError::QueryOrFragment);
    }
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if is_loopback(&parsed) => Ok(parsed),
        "http" => Err(AuthConfigError::InsecureRemoteAuthority),
        _ => Err(invalid),
    }
}

fn is_loopback(endpoint: &Url) -> bool {
    match endpoint.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        None => false,
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PUBLIC_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exact_public_configuration_without_enabling_auth() {
        let result = SharedAuthPublicClientConfig::try_new(
            "https://auth.example.test/shared-auth",
            "https://auth.example.test/customer",
            "hhm-desktop",
            "hhm-desktop-public",
        );
        assert!(result.is_ok());
        if let Ok(config) = result {
            assert_eq!(config.audience(), "hhm-desktop");
            assert_eq!(config.client_id(), "hhm-desktop-public");
            assert_eq!(config.authority().scheme(), "https");
            assert_eq!(config.issuer().scheme(), "https");
        }
    }

    #[test]
    fn rejects_remote_cleartext_credentials_and_url_metadata() {
        assert_eq!(
            SharedAuthPublicClientConfig::try_new(
                "http://auth.example.test",
                "https://auth.example.test/customer",
                "hhm-desktop",
                "hhm-desktop-public",
            ),
            Err(AuthConfigError::InsecureRemoteAuthority)
        );
        assert_eq!(
            SharedAuthPublicClientConfig::try_new(
                "https://user:secret@auth.example.test",
                "https://auth.example.test/customer",
                "hhm-desktop",
                "hhm-desktop-public",
            ),
            Err(AuthConfigError::EmbeddedCredentials)
        );
        assert_eq!(
            SharedAuthPublicClientConfig::try_new(
                "https://auth.example.test?token=forbidden",
                "https://auth.example.test/customer",
                "hhm-desktop",
                "hhm-desktop-public",
            ),
            Err(AuthConfigError::QueryOrFragment)
        );
    }

    #[test]
    fn permits_loopback_http_for_explicit_development() {
        assert!(
            SharedAuthPublicClientConfig::try_new(
                "http://127.0.0.1:8080/shared-auth",
                "http://localhost:8080/customer",
                "hhm-desktop-dev",
                "hhm-desktop-local",
            )
            .is_ok()
        );
    }
}
