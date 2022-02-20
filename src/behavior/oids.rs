
use crate::oids;

fn dump_oid(oid: &[u8]) -> String {
    format!("[u8;{}] = {:?}", oid.len(), oid)
}

pub fn oids() {
    
    println!(
        "pub const RSA_ENCRYPTION_BYTES: {};",
        &dump_oid(oids::RSA_ENCRYPTION.as_bytes())
    );
    println!(
        "pub const RSASSA_PSS_BYTES: {};",
        &dump_oid(oids::RSASSA_PSS.as_bytes())
    );
    println!(
        "pub const ECDSA_BYTES: {};",
        &dump_oid(oids::ECDSA.as_bytes())
    );
    println!(
        "pub const PRIME_256_V1_BYTES: {};",
        &dump_oid(oids::PRIME_256_V1.as_bytes())
    );
}
