mod bigint;
mod primes;
mod utils;

use crate::rsa::bigint::BigInt;
use crate::rsa::primes::prime_512_bit;
use crate::rsa::primes::are_coprimes;

struct KeyPair {
    public_key: Vec<BigInt>,
    private_key: Vec<BigInt>,
}

fn generate_keypair() -> KeyPair {
    let p = prime_512_bit();
    let q = prime_512_bit();
    let mut e: BigInt = BigInt::zero();

    let n = p * q;
    let phi = (p.decrease()) * (q.decrease());
    let possible_e = BigInt::from(2);

    while possible_e != phi {
        if are_coprimes(possible_e, phi) {
            e = possible_e;
            break;
        } else {
            possible_e.increase();
        }
    }

    if e == BigInt::zero() {
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
        private_key: vec![p, q, d],
    };
}
