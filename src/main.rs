pub mod aes_gcm;
pub mod rsa;
pub mod main_utils;
use std::fs;
use std::env;
use crate::aes_gcm::core::generate_128bit_key;
use crate::aes_gcm::core::core_encrypt;
use crate::aes_gcm::core::core_decrypt;

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
    fs::write("/home/thiago/gencheck-key/results/aes_key.txt", key).expect("Unable to write file");
}

fn rsa_oaep_decode() {
    let encoded_message = std::fs::read("/home/thiago/gencheck-key/results/rsa_encoded_message.txt").expect("Unable to read file");
    let auth_data = std::fs::read("/home/thiago/gencheck-key/results/rsa_auth_data.txt").expect("Unable to read file");
    let key_in_bytes = std::fs::read("/home/thiago/gencheck-key/results/rsa_private_key.txt").expect("Unable to read file");

    let data = rsa::rsa_oaep_decode(encoded_message, auth_data, key_in_bytes);

    fs::write("/home/thiago/gencheck-key/results/rsa_decoded_message.txt", data).expect("Unable to write file");
}

fn rsa_oaep_encode() {
    let message = std::fs::read("/home/thiago/gencheck-key/results/aes_key.txt").expect("Unable to read file");
    let auth_data = std::fs::read("/home/thiago/gencheck-key/results/rsa_auth_data.txt").expect("Unable to read file");
    let key_in_bytes = std::fs::read("/home/thiago/gencheck-key/results/rsa_public_key.txt").expect("Unable to read file");

    let data = rsa::rsa_oaep_encode(message, auth_data, key_in_bytes);

    fs::write("/home/thiago/gencheck-key/results/rsa_encoded_message.txt", data).expect("Unable to write file");
}

fn generate_rsa_keys() {
    let key_pair = rsa::generate_keypair();

    let public_key = main_utils::parse_key_to_byte(key_pair.public_key);
    let private_key = main_utils::parse_key_to_byte(key_pair.private_key);
    let public_key_in_right_order = main_utils::byte_reverse(&public_key);
    let private_key_in_right_order = main_utils::byte_reverse(&private_key);

    fs::write("/home/thiago/gencheck-key/results/rsa_public_key.txt", public_key_in_right_order).expect("Unable to write file");
    fs::write("/home/thiago/gencheck-key/results/rsa_private_key.txt", private_key_in_right_order).expect("Unable to write file");
}

fn aes_encode() {
    let key = std::fs::read("/home/thiago/gencheck-key/results/aes_key.txt").expect("Unable to read file");
    if key.len() != 16 {
        panic!("Key must be 16 bytes long");
    }
    
    let mut input = std::fs::read("/home/thiago/gencheck-key/results/aes_message.txt").expect("Unable to read file");
    let output = core_encrypt(&mut input, &key);

    fs::write("/home/thiago/gencheck-key/results/aes_encoded_message.txt", output).expect("Unable to write file");
}

fn aes_decode() {
    let key = std::fs::read("/home/thiago/gencheck-key/results/aes_key.txt").expect("Unable to read file");
    if key.len() != 16 {
        panic!("Key must be 16 bytes long");
    }
    
    let mut input = std::fs::read("/home/thiago/gencheck-key/results/aes_encoded_message.txt").expect("Unable to read file");   
    let output = core_decrypt(&mut input, &key);

    fs::write("/home/thiago/gencheck-key/results/aes_decoded_message.txt", output).expect("Unable to write file");
}