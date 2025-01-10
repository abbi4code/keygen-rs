use ed25519_dalek::{ed25519::signature::SignerMut, SigningKey};
use rand::{rngs::OsRng, RngCore}; //this will used to create random number (from os)
use sha2::{Digest, Sha512};
fn main() {
    //creating a signing key(includes both pub and pri keys)
    let mut csprng = OsRng {};
    //this will create a u8 arrays of 0's  with 32 element
    let mut private_key_bytes = [0u8; 32];
    //we will used this rnadom random no tobe work as a base to generate our private keys (this will be transformed into pkey that will fullfill the cryptographic requirements)
    // !depreciated
    // let signing_key = SigningKey::generate(&mut csprng);
    //this will fill random bytes in the arrays and this will servve as private key
    csprng.fill_bytes(&mut private_key_bytes);

    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let public_key = signing_key.verifying_key();

    // this is used to define a byte string literal diff from normal string which are &str
    //in cryptography we work on raw bytes rather than utf coded def strings
    let message = b"Hello rust";
    //now hashing the message
    let mut hasher = Sha512::new();
    hasher.update(message);
    let pre_hashedmsg = hasher.finalize();

    let signature = signing_key.sign(message);
    println!("Message: {:?}", String::from_utf8_lossy(message));
    println!("Signature: {:?}", signature.to_bytes());

    // let signature = signing_key.sign(message);

    // //verifying the signature
    // match public_key.verify(message, &signature) {
    //     Ok(_) => println!("Signature is valid"),
    //     Err(e) => println!("Signature is invalid: {}", e)
    // }

    //hit here heck
}
