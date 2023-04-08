# KeyPair-rs 
Keypair-rs is simple rust library for generating keypairs like used in ethreum. It is based on the sec256k1 library.
For hashing it uses the blake2b algorithm.

## Usage

```rs
use keypair::Keypair;

fn main() {
    let keypair = Keypair::generate();
    println!("public_key: {:?}", keypair.public_key);
    println!("private_key: {:?}", keypair.private_key);
    println!("address: {:?}", keypair.address());
    let message = "hello world".to_string();
    let signature = keypair.sign(message.clone()).unwrap();
    println!("signature: {:?}", signature);
    assert!(keypair.verify(&message, &signature).unwrap());
    
}
```