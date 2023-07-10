pub mod bigint;
mod primes;
mod utils;

use crate::rsa::bigint::BigInt;
use crate::rsa::primes::prime_512_bit;
use crate::rsa::primes::are_coprimes;
use crate::rsa::utils::insert_random_bytes;
use crate::main_utils::transform_u64_to_array_of_u8;
use crate::main_utils::reverse;
use crate::main_utils::parse_to_byte;
use crate::main_utils::byte_reverse;

use hex_literal::hex;
use sha2::{Sha256, Digest};

pub struct KeyPair {
    pub public_key: Vec<BigInt>,
    pub private_key: Vec<BigInt>,
}

pub fn rsa_oaep_decode(encoded_message: Vec<u8>, auth_data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let encoded_message_bigint_order = byte_reverse(&encoded_message);
    let key_bigint_order = byte_reverse(&key);

    let mut private_key: Vec<BigInt> = Vec::new();
    for (i, slice) in key_bigint_order.chunks(256).enumerate() {
        private_key.push(BigInt::from(slice));
    }

    let rsa_decoded_message = rsa_decrypt(BigInt::from(&encoded_message_bigint_order), private_key);
    let oaep_encoded_message_bigint_order = parse_to_byte(&rsa_decoded_message);
    let oaep_encoded_message = byte_reverse(&oaep_encoded_message_bigint_order);

    let oaep_decoded_message = oaep_decode(&oaep_encoded_message[128..], &auth_data);
    
    return oaep_decoded_message;
}

pub fn rsa_oaep_encode(message: Vec<u8>, auth_data: Vec<u8>, key: Vec<u8>) -> Vec<u8>{

    let key_bigint_order = byte_reverse(&key);

    let oaep_encoded_message = oaep_encode(&message, &auth_data);

    let reversed_message = byte_reverse(&oaep_encoded_message);

    let rsa_message = BigInt::from(&reversed_message);

    let mut public_key: Vec<BigInt> = Vec::new();

    for (i, slice) in key_bigint_order.chunks(256).enumerate() {
        public_key.push(BigInt::from(slice));
    }

    let encrypted_message = rsa_encrypt(rsa_message, public_key);

    let encrypted_message_bytes = parse_to_byte(&encrypted_message);
    return byte_reverse(&encrypted_message_bytes);
}


pub fn generate_keypair() -> KeyPair {
    let p = prime_512_bit();
    let q = prime_512_bit();

    let n = p * q;
    let phi = (p.decrease()) * (q.decrease());
    let mut e = BigInt::from(2);

    while e != phi {
        if are_coprimes(e, phi) {
            break;
        } else {
            e = e.increase();
        }
    }

    if e >= phi {
        panic!("Could not find a suitable e");
    }

    let d: BigInt;
    let mut possible_d_times_e = phi.clone() + BigInt::from(1);
    loop {
        if (possible_d_times_e % e).is_zero() {
            d = possible_d_times_e / e;
            break;
        } else {
            possible_d_times_e += phi;
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

fn concat_encoded_message(masked_seed: &[u8], masked_db: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = vec![0;128];
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

fn oaep_decode(encoded_message: &[u8], p: &[u8]) -> Vec<u8> {
    if encoded_message.len() < 2 * 32 + 1 {
        panic!("Decoding error: encoded message too short");
    }
    if encoded_message[0] != 0x00 {
        panic!("First byte of message is not 0x00");
    }

    let mut expected_phash: [u8; 32] = [0; 32];
    let mut hasher = Sha256::new();
    hasher.update(p);
    hasher.finalize_into((&mut expected_phash).into());

    
    let mut masked_seed: [u8; 32] = [0; 32];
    for i in 1..33 {
        masked_seed[i-1] = encoded_message[i];
    }

    let mut masked_db: Vec<u8> = Vec::new();
    for byte in encoded_message[33..encoded_message.len()].iter() {
        masked_db.push(*byte);
    }

    let seed_mask = mgf(&masked_db, 32);
    let mut seed: [u8; 32] = [0; 32];
    for i in 0..masked_seed.len() {
        seed[i] = masked_seed[i] ^ seed_mask[i];
    }

    let db_mask = mgf(&seed, (95) as u128);
    let mut db: Vec<u8> = Vec::new();
    for i in 0..masked_db.len() {
        db.push(masked_db[i] ^ db_mask[i]);
    }

    for i in 0..32 {
        if db[i] != expected_phash[i] {
            panic!("Decoding error: phash does not match");
        }
    }

    let mut message: Vec<u8> = Vec::new();
    let mut message_start: usize = 0;
    for i in 32..db.len() {
        if db[i] == 0x01 {
            message_start = i+1;
            break;
        } else if db[i] != 0x00 {
            panic!("PS not 0x00 (0x00 before 0x01)");
        }
    }

    if message_start == 0 {
        panic!("Not able to find message start");
    }

    for i in message_start..db.len() {
        message.push(db[i]);
    }

    return message;
}

/// message: message to be encoded, an octet string of length at most 
/// mLen = emLen − 1 − 2hLen (mLen denotes the length in octets of the message)
fn oaep_encode(message: &[u8], auth_data: &[u8]) -> Vec<u8> {

    // create a Sha256 object
    let mut hasher = Sha256::new();
    let padding_string: Vec<u8> = vec![0; 62 - message.len()];

    // 128 bytes come from the max size message of 1024 bits
    // 32 bytes comes from the output of the SHA-256 function 
    // 63 = 128 - 1 - 2 * 32
    // As we are encoding a AES key we should have plenty of space.
    // because we only need 16 bytes for the key.
    if message.len() > 62 {
        panic!("Message too long");
    }

    let mut phash: [u8; 32] = [0; 32];
    hasher.update(auth_data);
    hasher.finalize_into((&mut phash).into());

    let db = concat_db(&phash, &padding_string, &message);

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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa() {
        let key_pair = generate_keypair();
        let original_message = "Lorem ipsum dolor sit amet odio.";
        let reversed_message = reverse(original_message);
        let message = BigInt::from(reversed_message.as_bytes());

        let encrypted_message = rsa_encrypt(message, key_pair.public_key);
        let decrypted_message = rsa_decrypt(encrypted_message, key_pair.private_key);

        let mut final_message: Vec<u8> = Vec::new();
        let mut tmp: Vec<u8> = Vec::new();
        for byte in decrypted_message.chunks.iter() {
            tmp = transform_u64_to_array_of_u8(*byte);
            tmp.append(&mut final_message);
            final_message = tmp
            // final_message.append(&mut transform_u64_to_array_of_u8(*byte));
        }
    
        let binding = String::from_utf8(final_message).unwrap();
        let text_message = binding.trim_matches(char::from(0));
        assert_eq!(original_message, text_message);
    }

    #[test]
    fn test_oaep(){
        let message = "Very secret message";
        let auth_data = "VASCO";
        
        let encoded_message = oaep_encode(message.as_bytes(), auth_data.as_bytes());
        let mut decoded_message = oaep_decode(&encoded_message, auth_data.as_bytes());
        
        let binding = String::from_utf8(decoded_message).unwrap();
        let text_decoded_message = binding.trim_matches(char::from(0));

        assert_eq!(message, text_decoded_message);
    }
}