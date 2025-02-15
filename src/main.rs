
use ripemd::Ripemd160;
//so secp256k1 is elliptic curve which we used to create keys 
use secp256k1::{rand, Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};
use sha2::{Digest, Sha256};
use rand::thread_rng;
use base58::ToBase58;


fn generate_private_key()-> SecretKey {
    //we will use this late for creating public keys , during signatures
    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut thread_rng());
    secret_key
}

fn generate_public_key(secret_key: &SecretKey) -> PublicKey {

    let secp = Secp256k1::new();
    //Generates a random keypair. Convenience function for SecretKey::new and PublicKey::from_secret_key.
    let public_key = PublicKey::from_secret_key(&secp, secret_key);
    public_key

}

fn generate_bitcoin_address(public_key: &PublicKey) -> String {
    //so we will first hash then hash the result of sha hash using ripemd to shorten it then version byte for mainnet then again hash it using sha256 then encode it to base_58 then return

    let sha_hash = Sha256::digest(&public_key.serialize());
    // this will give result into hash or bytes

    //hashing it using ripemd 32 bytes to 20bytes

    let ripe_hash = Ripemd160::digest(&sha_hash);
    //same for this bytes or like string

    let mut extended = vec![0x00];
    extended.extend(&ripe_hash);
 // nwo this 21 bytes
 // we hash extended twice and take only first 4 btyes
    let checksum = &Sha256::digest(Sha256::digest(&extended))[..4];

    //extended is 21 bytes (20 bytes hashed ripe output and 1 0x00 and now )
    let mut full_extended = extended;

    full_extended.extend(checksum);


    full_extended.to_base58()


}

// so this will take msg and private key
fn sign_message(msg: &String, privatekey: &SecretKey ) -> secp256k1::ecdsa::Signature{

    //first need to convert the msg into bytes then hash 
    // then convert it to message type X
    // then need to sign the msg and get the signature and return it

    let secp = Secp256k1::new();

    let bytes_msg = Sha256::digest(msg.as_bytes());

    let message = Message::from_digest_slice(&bytes_msg).expect("32bytes msg needed");

    let signature = secp.sign_ecdsa(&message, privatekey);

    signature

}


fn main() {
    // this will create a hasher instance
    let mut hasher = Sha256::new();
    //this will add data to the hasher
    hasher.update("how are you");

    //finalize will taker this hasher and this will return 32 bytes arr
    let result = hasher.finalize();
    println!("SHA-256 Hash: {:x}", result);

    let private_key = generate_private_key();
    //so hex takes binary bytes data and convert into bytes format 
    println!("Private Key: {:?}", hex::encode(private_key.secret_bytes()));

    let public_key = generate_public_key(&private_key);

    //its 33bytes(compressed) and 65btyes (no compressed)
    //thsi public key is (x,y) point also in a obj form to convert this into a 33 byte format use serilaize

    println!("Public Key: {:?}", hex::encode(public_key.serialize_uncompressed()));


    let bitcoin_address = generate_bitcoin_address(&public_key);

    println!("bitcoin address: {:?}", bitcoin_address);


    let check_bytes = vec![0x00];

    println!("with :? {:?}", check_bytes);
    println!("without :? {}", hex::encode(&check_bytes));

    // let forcheck = &check_bytes;

    println!("base58endode {:?}", check_bytes.to_base58());

    let hardcoded_msg = String::from("value");

    let signature = sign_message(&hardcoded_msg, &private_key);

    println!("Signature: {:?}", signature);



    
    







}
