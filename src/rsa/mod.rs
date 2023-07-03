mod bigint;
mod primes;
mod utils;

use crate::rsa::bigint::BigInt;
use crate::rsa::primes::prime_512_bit;
use crate::rsa::primes::are_coprimes;
use crate::rsa::utils::mod_exp;

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

pub fn rsa_encrypt(message: BigInt, public_key: Vec<BigInt>) -> BigInt {
    let n = public_key[0];
    let e = public_key[1];

    return mod_exp(message, e, n);
}

pub fn rsa_decrypt(cipher_text: BigInt, private_key: Vec<BigInt>) -> BigInt {
    let n = private_key[0];
    let d = private_key[1];

    return mod_exp(cipher_text, d, n);
}
