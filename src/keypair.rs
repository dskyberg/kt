use pkcs8::PrivateKeyInfo;
use spki::SubjectPublicKeyInfo;

#[derive(Debug)]
pub struct KeyPair<'a> {
    pub private_key: Option<PrivateKeyInfo<'a>>,
    pub public_key: Option<SubjectPublicKeyInfo<'a>>,
}

impl<'a> KeyPair<'a> {
    pub fn new(
        private_key: Option<PrivateKeyInfo<'a>>,
        public_key: Option<SubjectPublicKeyInfo<'a>>,
    ) -> Self {
        Self {
            private_key,
            public_key,
        }
    }
}
