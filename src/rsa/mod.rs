use rand::Rng;

struct KeyPair {
    public_key: Vec<u128>,
    private_key: Vec<u128>,
}


fn generate_key_pair() -> KeyPair{
    let p: [u128; 8] = random_prime();
}

fn random_prime() -> [u128; 8] {
    let mut p: [u128; 8] = [0; 8];
    let mut rng = rand::thread_rng();

    loop {
        for i in 0..8 {
            p[i] = rng.gen();
        }

        if is_prime(p) {
            return p;
        }
    }
}

fn is_prime(){
    let b_max =  
}

