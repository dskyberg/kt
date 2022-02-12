use pkcs8::ObjectIdentifier;

pub const RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.10");
pub const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.1");
pub const ECDSA: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");
pub const PRIME_256_V1: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.3.1.7");

pub fn oid_to_str(oid: &ObjectIdentifier) -> String {
    match oid {
        &RSA_ENCRYPTION => format!("rsaEncryption: {}", oid),
        &RSASSA_PSS => format!("rsassaPss: {}", oid),
        &ECDSA => format!("id-ecPublicKey: {}", oid),
        &PRIME_256_V1 => format!("prime256v1: {}", oid),
        _ => format!("Unknown OID: {}", oid),
    }
}
