use std::fs::File;
use std::io::Read;

#[derive(PartialEq, Debug)]
pub enum PrimeResult {
    Prime,
    Composite,
    Unknown,
    ProbablePrime,
}

pub fn insert_random_bytes(bytes: &mut[u8]) -> std::io::Result<()> {
    File::open("/dev/urandom")?.read_exact(bytes)?;
    Ok(())
}

fn trial_division(n: u64, start: u64) -> PrimeResult {
    let root_n = (n as f64).sqrt() as u64;
    for x in (start..(root_n + 1)).step_by(6) {
        if n % x == 0 || n % (x + 2) == 0 {
            return PrimeResult::Composite;
        }
    }

    return PrimeResult::Prime;
}

pub fn generate_small_primes<const N:usize>() -> [u64; N] {
    let mut primes: [u64; N] = [0; N];
    primes[0] = 2;
    primes[1] = 3;

    let mut n: u64 = 3;
    let mut nth: u64 = 2;
    let mut i: usize = 2;
    let limit = N as u64;

    loop {
        n += 2;

        if trial_division(n, 5) == PrimeResult::Prime {
            primes[i] = n;
            i += 1;
            nth += 1;
            if nth == limit {
                return primes;
            }
        }
    }
}