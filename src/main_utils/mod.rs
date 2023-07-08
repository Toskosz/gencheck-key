use crate::rsa::bigint::BigInt;

pub fn transform_u64_to_array_of_u8(x:u64) -> Vec<u8> {
    let b1 : u8 = ((x >> 56) & 0xff) as u8;
    let b2 : u8 = ((x >> 48) & 0xff) as u8;
    let b3 : u8 = ((x >> 40) & 0xff) as u8;
    let b4 : u8 = ((x >> 32) & 0xff) as u8;
    let b5 : u8 = ((x >> 24) & 0xff) as u8;
    let b6 : u8 = ((x >> 16) & 0xff) as u8;
    let b7 : u8 = ((x >> 8) & 0xff) as u8;
    let b8 : u8 = (x & 0xff) as u8;
    return vec![b1, b2, b3, b4, b5, b6, b7, b8];
    // return vec![b8, b7, b6, b5, b4, b3, b2, b1];
}

pub fn reverse(s: &str) -> String {
    s.chars().rev().collect()
}