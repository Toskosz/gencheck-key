pub mod aes_gcm;
pub mod rsa;
pub mod main_utils;

use rsa::bigint::BigInt;
use rsa::generate_keypair;
use rsa::rsa_encrypt;
use rsa::rsa_decrypt;
use main_utils::transform_u64_to_array_of_u8;
use main_utils::reverse;

fn main() {
    println!("Hello, world!");
}
