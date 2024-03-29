pub mod aes_gcm;
pub mod rsa;
pub mod main_utils;
use std::fs;
use std::env;
use crate::aes_gcm::core::generate_128bit_key;
use crate::aes_gcm::core::core_encrypt;
use crate::aes_gcm::core::core_decrypt;

use base64::{Engine as _, engine::general_purpose};

fn main() {
    let args: Vec<String> = env::args().collect();

    let command = &args[1];
    if command == "generate_aes_key" {
        generate_aes_key();
    } else if command == "aes_encode" {
        aes_encode();
    } else if command == "aes_decode" {
        aes_decode();
    } else if command == "generate_rsa_key" {
        generate_rsa_keys();
    } else if command == "rsa_oaep_encode" {
        rsa_oaep_encode();
    } else if command == "rsa_oaep_decode" {
        rsa_oaep_decode();
    } else {
        panic!("Invalid command");
    }
}

fn generate_aes_key(){
    let key = generate_128bit_key();
    let base_64_encoded: String = general_purpose::STANDARD_NO_PAD.encode(key);
    fs::write("./results/aes_key.txt", base_64_encoded).expect("Unable to write file");
}

fn rsa_oaep_decode() {
    let mut encoded_message = std::fs::read("./results/rsa_encoded_message.txt").expect("Unable to read file");
    encoded_message = general_purpose::STANDARD_NO_PAD.decode(encoded_message).unwrap();

    let auth_data = std::fs::read("./results/rsa_auth_data.txt").expect("Unable to read file");
    let mut key_in_bytes = std::fs::read("./results/rsa_private_key.txt").expect("Unable to read file");

    key_in_bytes = general_purpose::STANDARD_NO_PAD.decode(key_in_bytes).unwrap();

    let data = rsa::rsa_oaep_decode(encoded_message, auth_data, key_in_bytes);

    let base_64_encoded: String = general_purpose::STANDARD_NO_PAD.encode(data);

    fs::write("./results/rsa_decoded_message.txt", base_64_encoded).expect("Unable to write file");
}

fn rsa_oaep_encode() {
    let mut message = std::fs::read("./results/aes_key.txt").expect("Unable to read file");
    message = general_purpose::STANDARD_NO_PAD.decode(message).unwrap();

    let auth_data = std::fs::read("./results/rsa_auth_data.txt").expect("Unable to read file");

    let mut key_in_bytes = std::fs::read("./results/rsa_public_key.txt").expect("Unable to read file");
    key_in_bytes = general_purpose::STANDARD_NO_PAD.decode(key_in_bytes).unwrap();

    let data = rsa::rsa_oaep_encode(message, auth_data, key_in_bytes);

    let base_64_encoded: String = general_purpose::STANDARD_NO_PAD.encode(data);

    fs::write("./results/rsa_encoded_message.txt", base_64_encoded).expect("Unable to write file");
}

fn generate_rsa_keys() {
    let key_pair = rsa::generate_keypair();

    let public_key = main_utils::parse_key_to_byte(key_pair.public_key);
    let private_key = main_utils::parse_key_to_byte(key_pair.private_key);
    let public_key_in_right_order = main_utils::byte_reverse(&public_key);
    let private_key_in_right_order = main_utils::byte_reverse(&private_key);

    let base_64_encoded_p: String = general_purpose::STANDARD_NO_PAD.encode(public_key_in_right_order);
    let base_64_encoded_s: String = general_purpose::STANDARD_NO_PAD.encode(private_key_in_right_order);

    fs::write("./results/rsa_public_key.txt", base_64_encoded_p).expect("Unable to write file");
    fs::write("./results/rsa_private_key.txt", base_64_encoded_s).expect("Unable to write file");
}

fn aes_encode() {
    let mut key = std::fs::read("./results/aes_key.txt").expect("Unable to read file");
    key = general_purpose::STANDARD_NO_PAD.decode(key).unwrap();

    if key.len() != 16 {
        panic!("Key must be 16 bytes long");
    }
    
    let mut input = std::fs::read("./results/aes_message.txt").expect("Unable to read file");
    let output = core_encrypt(&mut input, &key);

    let base_64_encoded: String = general_purpose::STANDARD_NO_PAD.encode(output);

    fs::write("./results/aes_encoded_message.txt", base_64_encoded).expect("Unable to write file");
}

fn aes_decode() {
    let mut key = std::fs::read("./results/aes_key.txt").expect("Unable to read file");
    key = general_purpose::STANDARD_NO_PAD.decode(key).unwrap();
    if key.len() != 16 {
        panic!("Key must be 16 bytes long");
    }
    
    let mut input = std::fs::read("./results/aes_encoded_message.txt").expect("Unable to read file");   
    
    input = general_purpose::STANDARD_NO_PAD.decode(input).unwrap();
    
    let output = core_decrypt(&mut input, &key);

    fs::write("./results/aes_decoded_message.txt", output).expect("Unable to write file");
}