use crate::crypto::hash;

use secp256k1::hashes::sha256;
use secp256k1::{Message, PublicKey,SecretKey, Secp256k1, ecdsa::Signature as Signature};
use rand::rngs::OsRng;

#[derive(Debug, Clone)]
pub struct Keypair {
    pub public_key: String,
    pub private_key: String,
}

impl Keypair {
    pub fn address(&self) -> String {
        format!(
            "0x{}",
            hash(hex::decode(&self.public_key).unwrap())[..40].to_string()
        )
    }

    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let (secret_key, public_key) = secp.generate_keypair(&mut rng);
        // Keypair {
        //     private_key: secret_key.to_string(),
        //     public_key: public_key.to_string(),
        // }
        Keypair {
            private_key: secret_key.display_secret().to_string(),
            public_key: public_key.to_string(),
        }
    }

    pub fn sign(&self, message: String) -> Result<String, Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();
        let a = hex::decode(&self.private_key).unwrap();
        // let secretkey = secp256k1::key::SecretKey::from_slice(&a);
        let secretkey = SecretKey::from_slice(&a);
        let msg = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());
        let sig = secp.sign_ecdsa(&msg, &secretkey.unwrap());
        Ok(hex::encode(sig.serialize_der().to_vec()))
    }

    pub fn verify(
        &self,
        message: &String,
        signature: &String,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let sig_bytes = hex::decode(signature)?;
        let signature: Signature = Signature::from_der(&sig_bytes)?;
        let secp = Secp256k1::new();
        let pk_bytes = hex::decode(self.public_key.as_bytes());
        let publickey = PublicKey::from_slice(&pk_bytes.unwrap())?;
        let msg = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());
        return Ok(secp.verify_ecdsa(&msg, &signature, &publickey).is_ok());
    }

    pub fn from_private_key(pk: String) -> Keypair {
        let privatekeyclone = pk.clone();
        let a = hex::decode(&pk).unwrap();
        let secretkey = SecretKey::from_slice(&a);
        let secp = &Secp256k1::new();
        // let public_key = secp256k1::key::PublicKey::from_secret_key(secp, &secretkey.unwrap());
        let public_key = PublicKey::from_secret_key(secp, &secretkey.unwrap());
        Keypair {
            private_key: privatekeyclone.to_string(),
            public_key: public_key.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair() {
        let keypair = Keypair::generate();
        let message = "hello world".to_string();
        let signature = keypair.sign(message.clone()).unwrap();
        assert!(keypair.verify(&message, &signature).unwrap());
        println!("keypair: {:?}", keypair);
        println!("address: {:?}", keypair.address());

    }
    #[test]
    fn test_from_private_key() {
        let keypair = Keypair::generate();
        let keypair2 = Keypair::from_private_key(keypair.private_key.clone());
        assert_eq!(keypair.private_key, keypair2.private_key);
        assert_eq!(keypair.public_key, keypair2.public_key);
        println!("keypair: {:?}", keypair);
    }
    #[test]
    fn test_address() {
        let keypair = Keypair::generate();
        let address = keypair.address();
        println!("address: {:?}", address);
    }
    // cargo test -- --nocapture
}

