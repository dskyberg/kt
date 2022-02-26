use pkcs8::ObjectIdentifier;

pub const RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.10");
pub const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.1");
pub const ECDSA: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");
pub const PRIME_256_V1: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.3.1.7");
pub const X25519: ObjectIdentifier = ObjectIdentifier::new("1.3.101.110");
pub const X448: ObjectIdentifier = ObjectIdentifier::new("1.3.101.111");
pub const ED_DSA25519: ObjectIdentifier = ObjectIdentifier::new("1.3.101.112");
pub const ED_DSA448: ObjectIdentifier = ObjectIdentifier::new("1.3.101.113");
pub const ED_DSA25519_PH: ObjectIdentifier = ObjectIdentifier::new("1.3.101.114");
pub const ED_DSA448_PH: ObjectIdentifier = ObjectIdentifier::new("1.3.101.115");

pub const RSA_ENCRYPTION_BYTES: [u8; 9] = [42, 134, 72, 134, 247, 13, 1, 1, 1];
pub const RSASSA_PSS_BYTES: [u8; 9] = [42, 134, 72, 134, 247, 13, 1, 1, 10];
pub const ECDSA_BYTES: [u8; 7] = [42, 134, 72, 206, 61, 2, 1];
pub const PRIME_256_V1_BYTES: [u8; 8] = [42, 134, 72, 206, 61, 3, 1, 7];
pub const X25519_BYTES: [u8;3] = [43, 101, 110];
pub const X448_BYTES: [u8;3] = [43, 101, 111];
pub const ED_DSA25519_BYTES: [u8;3] = [43, 101, 112];
pub const ED_DSA448_BYTES: [u8;3] = [43, 101, 113];
pub const ED_DSA25519_PH_BYTES: [u8;3] = [43, 101, 114];
pub const ED_DSA448_PH_BYTES: [u8;3] = [43, 101, 115];


pub fn oid_to_str(oid: &ObjectIdentifier) -> String {
    match *oid {
        RSA_ENCRYPTION => format!("rsaEncryption: {}", oid),
        RSASSA_PSS => format!("rsassaPss: {}", oid),
        ECDSA => format!("id-ecPublicKey: {}", oid),
        PRIME_256_V1 => format!("prime256v1: {}", oid),
        X25519 => format!("id-X25519: {}", oid),
        X448 => format!("id-X448: {}", oid),
        ED_DSA25519 => format!("id-EdDSA25519: {}", oid),
        ED_DSA448 => format!("id-EdDSA448-ph: {}", oid),
        ED_DSA25519_PH => format!("id-EdDS25519-ph: {}", oid),
        ED_DSA448_PH=> format!("id-EdDSA448-ph: {}", oid),
        _ => format!("Unknown OID: {}", oid),
    }
}
