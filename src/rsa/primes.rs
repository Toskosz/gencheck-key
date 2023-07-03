use crate::rsa::utils;
use crate::rsa::bigint::BigInt;
use crate::rsa::bigint::gcd;

pub fn prime_512_bit() -> BigInt {
    const P: usize = 5000;

    let primes = utils::generate_small_primes::<P>();

    let zero = BigInt::zero();
    let mut small_prime = BigInt::zero();

    let mut num = BigInt::random();
    num.modify();

    'prime_loop: loop {
        num = num.increase_by_two();

        for i in 0..P {
            small_prime.chunks[0] = primes[i];
            if num % small_prime == zero {
                continue 'prime_loop;
            }
        }

        if miller_rabin_test(num, 10) == utils::PrimeResult::ProbablePrime {
            return num;
        }
    }
}

fn miller_rabin_test(n: BigInt, k:usize) -> utils::PrimeResult {
    let zero = BigInt::zero();
    let one = BigInt::from(1);

    let mut s = zero;
    let n_minus_one = n.decrease();

    let mut d = n_minus_one;
    while d.is_even() {
        d >>= 1;
        s = s.increase();
    }

    let mut bytes = [0; (512/16)];
    let mut x;
    let mut base;

    'main_loop: for _ in 0..k {
        utils::insert_random_bytes(&mut bytes).unwrap();
        base = BigInt::from(bytes.as_slice());

        x = one;

        while !d.is_zero() {
            if !d.is_even() {
                x = (x * base) % n;
            }
            d = d >> 1;
            base = (base * base ) % n;
        }

        if x == one || x == n_minus_one {continue 'main_loop;}

        while !s.is_zero() {
            x = (x * x) % n;
            if x == n_minus_one {continue 'main_loop;}
            s = s.decrease();
        }

        return utils::PrimeResult::Composite;
    }

    return utils::PrimeResult::ProbablePrime;
}

pub fn are_coprimes(a: BigInt, b: BigInt) -> bool {
    if a.is_even() && b.is_even() {
        return false;
    }
    return gcd(a, b) == BigInt::from(1);
}