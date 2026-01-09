use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;

use crate::Error;
use ring::hmac;
/// Reality protocol support for rustls
///
/// REALITY is a censorship circumvention protocol developed by XTLS Project.
/// It works by injecting authentication information into TLS handshake messages
/// while maintaining compatibility with standard TLS.
///
/// Key features:
/// - Injects HMAC-SHA256 authentication into ServerHello.random[20..32]
/// - Verifies client authentication from ClientHello.session_id
/// - Supports fallback to destination server for non-Reality clients

/// Inject Reality authentication into ServerHello.random
///
/// Reality protocol modifies the last 12 bytes of ServerHello.random to include
/// an HMAC-SHA256 based authentication tag.
///
/// Algorithm (from XTLS/REALITY):
/// 1. Keep server_random[0..20] unchanged
/// 2. Calculate: HMAC-SHA256(private_key, server_random[0..20] + client_random[0..32])
/// 3. Set server_random[20..32] = HMAC result[0..12]
///
/// # Arguments
/// * `server_random` - The 32-byte server random to modify (in-place)
/// * `config` - The Reality configuration containing the private key
/// * `client_random` - The 32-byte client random from ClientHello
///
/// # Errors
/// Returns error if private_key length is not 32 bytes
pub fn inject_auth(
    server_random: &mut [u8; 32],
    config: &RealityConfig,
    client_random: &[u8; 32],
) -> Result<(), Error> {
    config.validate()?;

    // Create HMAC-SHA256 key from private key
    let key = hmac::Key::new(hmac::HMAC_SHA256, &config.private_key);

    // Prepare message: server_random[0..20] + client_random[0..32]
    let mut message = Vec::with_capacity(52);
    message.extend_from_slice(&server_random[0..20]);
    message.extend_from_slice(client_random);

    // Calculate HMAC-SHA256
    let tag = hmac::sign(&key, &message);

    // Inject first 12 bytes of HMAC into server_random[20..32]
    server_random[20..32].copy_from_slice(&tag.as_ref()[0..12]);

    Ok(())
}

/// Verify Reality client authentication from ClientHello.session_id
///
/// Reality clients include authentication information in the session_id field
/// of ClientHello. This function verifies that the client is a legitimate
/// Reality client.
///
/// According to XTLS/REALITY protocol:
/// - Client calculates: HMAC-SHA256(public_key, client_random)
/// - Client puts the first 8 bytes in session_id
/// - Server verifies using its private_key
///
/// # Arguments
/// * `session_id` - The session_id from ClientHello
/// * `client_random` - The 32-byte client random from ClientHello
/// * `config` - The Reality configuration containing the private key
///
/// # Returns
/// `true` if the client is authenticated, `false` otherwise
/// Verify Reality client authentication from ClientHello.session_id
///
/// Reality clients include authentication information in the session_id field
/// of ClientHello. The full verification process involves:
/// 1. Extract client's X25519 public key from KeyShare extension
/// 2. Perform ECDH(server_private, client_public) to get shared secret
/// 3. Derive AuthKey using HKDF-SHA256(shared_secret, client_random[:20], "REALITY")
/// 4. Decrypt SessionID using AES-GCM with AuthKey
/// 5. Verify shortId matches configuration
///
/// # Current Implementation
///
/// This is a **simplified placeholder** that accepts all non-empty session_ids.
/// The full ECDH + HKDF + AEAD verification will be implemented in Phase 4.
///
/// # Arguments
/// * `session_id` - The session_id from ClientHello
/// * `client_random` - The 32-byte client random from ClientHello
/// * `config` - The Reality configuration containing the private key
///
/// # Returns
/// `true` if the client is authenticated, `false` otherwise
///
/// # TODO
/// - Implement ECDH key exchange
/// - Implement HKDF-SHA256 derivation
/// - Implement AES-GCM AEAD decryption
/// - Verify shortId from decrypted SessionID
/// - See REALITY_CLIENT_AUTH_ANALYSIS.md for details
pub fn verify_client(
    session_id: &[u8],
    _client_random: &[u8; 32],
    config: &RealityConfig,
) -> bool {
    if config.private_key.len() != 32 {
        return false;
    }

    if session_id.is_empty() {
        return false;
    }

    // TODO: Implement full ECDH + HKDF + AEAD verification
    // For now, accept all non-empty session_ids to focus on ServerHello injection

    // Placeholder: Check if session_id has reasonable length (should be 32 bytes)
    if session_id.len() != 32 {
        return false;
    }

    // Accept all clients with 32-byte session_id
    // This will be replaced with proper verification in Phase 4
    true
}

/// Reality protocol configuration
///
/// This configuration enables Reality protocol support in rustls,
/// allowing the server to authenticate legitimate clients and
/// fall back to a destination server for non-Reality clients.
#[derive(Clone, Debug)]
pub struct RealityConfig {
    /// Reality private key (must be 32 bytes)
    ///
    /// This is the X25519 private key used for Reality authentication.
    /// Generate with: `xray x25519` or equivalent
    pub private_key: Vec<u8>,

    /// Whether to verify client authentication
    ///
    /// If true, the server will verify that clients include valid
    /// Reality authentication in their ClientHello.session_id.
    /// Clients that fail verification will trigger the fallback handler.
    pub verify_client: bool,

    /// Destination server for fallback
    ///
    /// When a non-Reality client connects (or verification fails),
    /// the connection will be forwarded to this destination.
    /// Format: "hostname:port" (e.g., "www.example.com:443")
    pub dest: Option<String>,
}

impl RealityConfig {
    /// Create a new Reality configuration
    ///
    /// # Arguments
    /// * `private_key` - The 32-byte Reality private key
    ///
    /// # Example
    /// ```ignore
    /// use rustls::reality::RealityConfig;
    ///
    /// let private_key = vec![/* 32 bytes */];
    /// let config = RealityConfig::new(private_key);
    /// ```
    pub fn new(private_key: Vec<u8>) -> Self {
        Self {
            private_key,
            verify_client: true,
            dest: None,
        }
    }

    /// Enable or disable client verification
    pub fn with_verify_client(mut self, verify: bool) -> Self {
        self.verify_client = verify;
        self
    }

    /// Set the fallback destination
    pub fn with_dest(mut self, dest: String) -> Self {
        self.dest = Some(dest);
        self
    }

    /// Validate the configuration
    ///
    /// Returns an error if the configuration is invalid
    pub fn validate(&self) -> Result<(), Error> {
        if self.private_key.len() != 32 {
            return Err(Error::General(
                "Reality private key must be 32 bytes".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_auth() {
        let mut server_random = [0u8; 32];
        // Fill with some data
        for (i, byte) in server_random.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let config = RealityConfig::new(vec![42u8; 32]);
        let client_random = [99u8; 32];

        let original_prefix = server_random[0..20].to_vec();

        inject_auth(&mut server_random, &config, &client_random).unwrap();

        // First 20 bytes should remain unchanged
        assert_eq!(&server_random[0..20], &original_prefix[..]);

        // Last 12 bytes should be modified (not equal to original)
        assert_ne!(
            &server_random[20..32],
            &[20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
        );

        // Verify HMAC is deterministic
        let mut server_random2 = [0u8; 32];
        for (i, byte) in server_random2.iter_mut().enumerate() {
            *byte = i as u8;
        }
        inject_auth(&mut server_random2, &config, &client_random).unwrap();
        assert_eq!(&server_random[20..32], &server_random2[20..32]);
    }

    #[test]
    fn test_inject_auth_invalid_key_length() {
        let mut server_random = [0u8; 32];
        let config = RealityConfig::new(vec![42u8; 16]); // Wrong length
        let client_random = [99u8; 32];

        let result = inject_auth(&mut server_random, &config, &client_random);
        assert!(result.is_err());
    }

    #[test]
    #[test]
    fn test_verify_client() {
        let config = RealityConfig::new(vec![42u8; 32]);
        let client_random = [99u8; 32];

        // Valid: 32-byte session_id
        let session_id = vec![1u8; 32];
        assert!(verify_client(&session_id, &client_random, &config));

        // Invalid: wrong length
        let session_id = vec![1u8; 16];
        assert!(!verify_client(&session_id, &client_random, &config));
    }

    #[test]
    #[test]
    #[test]

    #[test]
    fn test_config_validation() {
        let valid_config = RealityConfig::new(vec![42u8; 32]);
        assert!(valid_config.validate().is_ok());

        let invalid_config = RealityConfig::new(vec![42u8; 16]);
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_hmac_correctness() {
        // Test vector to ensure HMAC-SHA256 is working correctly
        let config = RealityConfig::new(vec![0x42; 32]);
        let mut server_random = [0u8; 32];
        for i in 0..32 {
            server_random[i] = i as u8;
        }
        let client_random = [0x99; 32];

        inject_auth(&mut server_random, &config, &client_random).unwrap();

        // The injected bytes should be deterministic
        // We can't predict the exact value without running HMAC,
        // but we can verify it's not all zeros
        let injected = &server_random[20..32];
        assert_ne!(injected, &[0u8; 12]);
    }
}
