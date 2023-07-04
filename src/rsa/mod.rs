mod bigint;
mod primes;
mod utils;

use crate::rsa::bigint::BigInt;
use crate::rsa::primes::prime_512_bit;
use crate::rsa::primes::are_coprimes;
use crate::rsa::utils::insert_random_bytes;

use hex_literal::hex;
use sha2::{Sha256, Digest};

pub struct KeyPair {
    public_key: Vec<BigInt>,
    private_key: Vec<BigInt>,
}

pub fn generate_keypair() -> KeyPair {
    let p = prime_512_bit();
    let q = prime_512_bit();

    let n = p * q;
    let phi = (p.decrease()) * (q.decrease());
    let e = BigInt::from(2);

    while e != phi {
        if are_coprimes(e, phi) {
            break;
        } else {
            e.increase();
        }
    }

    if e == BigInt::from(2) {
        panic!("Could not find a suitable e");
    }

    let d: BigInt = BigInt::from(1);
    loop {
        if (d * e) % phi == BigInt::from(1) {
            break;
        } else {
            d.increase();
        } 
    }

    return KeyPair {
        public_key: vec![n, e],
        private_key: vec![n, d],
    };
}

fn mod_exp(mut base: BigInt, mut exponent: BigInt, modulus: BigInt) -> BigInt {
    if modulus == BigInt::from(1) { return BigInt::zero() }

    let mut result = BigInt::from(1);
    base = base % modulus;
    while exponent > BigInt::zero() {
        if exponent % BigInt::from(2) == BigInt::from(1) {
            result = (result * base) % modulus;
        }
        exponent = exponent >> 1;
        base = (base * base) % modulus;
    }
    return result;
}

fn rsa_encrypt(message: BigInt, public_key: Vec<BigInt>) -> BigInt {
    let n = public_key[0];
    let e = public_key[1];

    return mod_exp(message, e, n);
}

fn rsa_decrypt(cipher_text: BigInt, private_key: Vec<BigInt>) -> BigInt {
    let n = private_key[0];
    let d = private_key[1];

    return mod_exp(cipher_text, d, n);
}

fn concat_db(phash: &[u8], ps: &[u8], message: &[u8]) -> [u8; 95] {
    
    // 95 = 128 - 32 - 1
    let mut concat: [u8; 95] = [0; 95];
    let mut i = 0;

    for byte in phash {
        concat[i] = *byte;
        i += 1;
    }
    for byte in ps {
        concat[i] = *byte;
        i += 1;
    }
    concat[i] = 0x01;
    i += 1;
    for byte in message {
        concat[i] = *byte;
        i += 1;
    }
    return concat;
}

fn concat_encoded_message(masked_seed: &[u8], masked_db: &[u8]) -> [u8; 128] {
    let mut result: [u8; 128] = [0;128];
    result[0] = 0x00;
    let mut i = 1;
    for byte in masked_seed {
        result[i] = *byte;
        i += 1;
    }
    for byte in masked_db {
        result[i] = *byte;
        i += 1;
    }
    return result;
}

fn mgf(input: &[u8], output_length: u128) -> Vec<u8>{
    if output_length > 2_u128.pow(32) * 32{
        panic!("Output length too long");
    }

    let mut hasher = Sha256::new();
    let mut hash:[u8; 32] = [0; 32];
    let mut t: Vec<u8> = vec![0; output_length as usize];
    let mut concat: Vec<u8>;
    let mut i_bytes: [u8; 16];

    for i in 0..(output_length/32) - 1 {
        i_bytes = (i as u128).to_be_bytes();

        concat = input.to_vec();
        for byte in i_bytes[..4].iter(){
            concat.push(*byte);
        }

        hasher = Sha256::new();
        hasher.update(concat);
        hasher.finalize_into((&mut hash).into());

        for byte in hash{
            t.push(byte);
        }
    }

    return t[0..output_length as usize].to_vec();
}

/// message: message to be encoded, an octet string of length at most 
/// emLen − 1 − 2hLen (mLen denotes the length in octets of the message
fn oaep_encode(message: &[u8]) -> [u8;128] {

    // create a Sha256 object
    let mut hasher = Sha256::new();

    // 128 bytes come from the max size message of 1024 bits
    // 32 bytes comes from the output of the SHA-256 function 
    // 63 = 128 - 1 - 2 * 32
    // As we are encoding a AES key we should have plenty of space.
    // because we only need 16 bytes for the key.
    if message.len() > 62 {
        panic!("Message too long");
    }

    let ps: Vec<u8> = vec![0; 62 - message.len()];
    
    // 32 is a arbitrary choice of mine
    // It can be any size between 1 and SHA-256 input limit  
    let p: [u8; 32] = [0; 32];
    // insert_random_bytes(&mut p).expect("Failed to generate random bytes for P in OAEP");

    let mut phash: [u8; 32] = [0; 32];

    // write input message
    hasher.update(p);
    // read hash digest and consume hasher
    hasher.finalize_into((&mut phash).into());

    let db = concat_db(&phash, &ps, &message);

    let mut seed: [u8; 32] = [0; 32];
    insert_random_bytes(&mut seed).expect("Failed to generate random seed in OAEP");

    let db_mask = mgf(&seed, 95);

    let mut masked_db: [u8; 95] = [0; 95];
    for i in 0..masked_db.len() {
        masked_db[i] = db[i] ^ db_mask[i];
    }

    let seed_mask = mgf(&masked_db, 32);
    
    let mut masked_seed: [u8; 32] = [0; 32];
    for i in 0..masked_seed.len() {
        masked_seed[i] = seed[i] ^ seed_mask[i];
    }

    let encoded_message = concat_encoded_message(&masked_seed, &masked_db);
    
    return encoded_message;
}