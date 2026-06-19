//! Ed25519 signed structures for security.

use crate::DCPError;

/// Ed25519 signed tool definition
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedToolDef {
    /// Tool identifier
    pub tool_id: u32,
    /// Blake3 hash of schema
    pub schema_hash: [u8; 32],
    /// Required capabilities bitfield
    pub capabilities: u64,
    /// Ed25519 signature
    pub signature: [u8; 64],
    /// Signer's public key
    pub public_key: [u8; 32],
}

/// Signed invocation with replay protection
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedInvocation {
    /// Tool identifier
    pub tool_id: u32,
    /// Unique nonce for replay protection
    pub nonce: u64,
    /// Timestamp for expiration
    pub timestamp: u64,
    /// Blake3 hash of arguments
    pub args_hash: [u8; 32],
    /// Ed25519 signature
    pub signature: [u8; 64],
}

impl SignedToolDef {
    /// Size of the struct in bytes
    pub const SIZE: usize = 144; // 4 + 32 + 8 + 64 + 32 + padding

    /// Size of the compact payload covered by the signature.
    pub const SIGNED_BYTES_SIZE: usize = 44;

    /// Parse from canonical bytes.
    #[inline(always)]
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, DCPError> {
        let bytes = bytes.as_ref();
        if bytes.len() < Self::SIZE {
            return Err(DCPError::InsufficientData);
        }
        if bytes.len() != Self::SIZE {
            return Err(DCPError::ValidationFailed);
        }
        if bytes[36..40].iter().any(|&byte| byte != 0) {
            return Err(DCPError::ValidationFailed);
        }

        let mut schema_hash = [0u8; 32];
        schema_hash.copy_from_slice(&bytes[4..36]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[48..112]);
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[112..144]);

        Ok(Self {
            tool_id: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            schema_hash,
            capabilities: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            signature,
            public_key,
        })
    }

    /// Serialize to canonical bytes with reserved padding zeroed.
    #[inline(always)]
    pub fn as_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..4].copy_from_slice(&self.tool_id.to_le_bytes());
        bytes[4..36].copy_from_slice(&self.schema_hash);
        bytes[40..48].copy_from_slice(&self.capabilities.to_le_bytes());
        bytes[48..112].copy_from_slice(&self.signature);
        bytes[112..144].copy_from_slice(&self.public_key);
        bytes
    }

    /// Get the compact bytes covered by the signature.
    pub fn signed_bytes(&self) -> [u8; Self::SIGNED_BYTES_SIZE] {
        let mut bytes = [0u8; Self::SIGNED_BYTES_SIZE];
        bytes[0..4].copy_from_slice(&self.tool_id.to_le_bytes());
        bytes[4..36].copy_from_slice(&self.schema_hash);
        bytes[36..44].copy_from_slice(&self.capabilities.to_le_bytes());
        bytes
    }
}

impl SignedInvocation {
    /// Size of the struct in bytes
    pub const SIZE: usize = 120; // 4 + 8 + 8 + 32 + 64 + padding

    /// Size of the compact payload covered by the signature.
    pub const SIGNED_BYTES_SIZE: usize = 52;

    /// Parse from canonical bytes.
    #[inline(always)]
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, DCPError> {
        let bytes = bytes.as_ref();
        if bytes.len() < Self::SIZE {
            return Err(DCPError::InsufficientData);
        }
        if bytes.len() != Self::SIZE {
            return Err(DCPError::ValidationFailed);
        }
        if bytes[4..8].iter().any(|&byte| byte != 0) {
            return Err(DCPError::ValidationFailed);
        }

        let mut args_hash = [0u8; 32];
        args_hash.copy_from_slice(&bytes[24..56]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[56..120]);

        Ok(Self {
            tool_id: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            nonce: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            timestamp: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            args_hash,
            signature,
        })
    }

    /// Serialize to canonical bytes with reserved padding zeroed.
    #[inline(always)]
    pub fn as_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..4].copy_from_slice(&self.tool_id.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.nonce.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.timestamp.to_le_bytes());
        bytes[24..56].copy_from_slice(&self.args_hash);
        bytes[56..120].copy_from_slice(&self.signature);
        bytes
    }

    /// Get the compact bytes covered by the signature.
    pub fn signed_bytes(&self) -> [u8; Self::SIGNED_BYTES_SIZE] {
        let mut bytes = [0u8; Self::SIGNED_BYTES_SIZE];
        bytes[0..4].copy_from_slice(&self.tool_id.to_le_bytes());
        bytes[4..12].copy_from_slice(&self.nonce.to_le_bytes());
        bytes[12..20].copy_from_slice(&self.timestamp.to_le_bytes());
        bytes[20..52].copy_from_slice(&self.args_hash);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_tool_def_size() {
        assert_eq!(std::mem::size_of::<SignedToolDef>(), SignedToolDef::SIZE);
    }

    #[test]
    fn test_signed_invocation_size() {
        assert_eq!(
            std::mem::size_of::<SignedInvocation>(),
            SignedInvocation::SIZE
        );
    }

    #[test]
    fn test_signed_tool_def_round_trip() {
        let def = SignedToolDef {
            tool_id: 42,
            schema_hash: [0xAB; 32],
            capabilities: 0x1234567890ABCDEF,
            signature: [0xCD; 64],
            public_key: [0xEF; 32],
        };
        let bytes = def.as_bytes();
        let parsed = SignedToolDef::from_bytes(bytes).unwrap();

        assert_eq!(parsed.tool_id, 42);
        assert_eq!(parsed.schema_hash, [0xAB; 32]);
        assert_eq!(parsed.capabilities, 0x1234567890ABCDEF);
        assert_eq!(parsed.signature, [0xCD; 64]);
        assert_eq!(parsed.public_key, [0xEF; 32]);
    }

    #[test]
    fn test_signed_invocation_round_trip() {
        let inv = SignedInvocation {
            tool_id: 123,
            nonce: 0xDEADBEEF,
            timestamp: 1234567890,
            args_hash: [0x11; 32],
            signature: [0x22; 64],
        };
        let bytes = inv.as_bytes();
        let parsed = SignedInvocation::from_bytes(bytes).unwrap();

        assert_eq!(parsed.tool_id, 123);
        assert_eq!(parsed.nonce, 0xDEADBEEF);
        assert_eq!(parsed.timestamp, 1234567890);
        assert_eq!(parsed.args_hash, [0x11; 32]);
        assert_eq!(parsed.signature, [0x22; 64]);
    }

    #[test]
    fn test_signed_bytes_length() {
        let def = SignedToolDef {
            tool_id: 0,
            schema_hash: [0; 32],
            capabilities: 0,
            signature: [0; 64],
            public_key: [0; 32],
        };
        assert_eq!(def.signed_bytes().len(), 44);

        let inv = SignedInvocation {
            tool_id: 0,
            nonce: 0,
            timestamp: 0,
            args_hash: [0; 32],
            signature: [0; 64],
        };
        assert_eq!(inv.signed_bytes().len(), 52);
    }
}
