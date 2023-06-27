mod utils;
mod core;
use crate::aes_gcm::core::*;
use crate::aes_gcm::utils::*;

pub struct AesGcm {
    expanded_key: [u32; 44]
}

impl AesGcm {
    fn new(key: &[u8]) -> AesGcm {
        AesGcm {
            expanded_key: key_expansion(key)
        }
    }

    fn encrypt(&self, cipher_text: &mut[u8], plain_text: &[u8], auth_data: &[u8]) {
        // TODO: manipulatation to make sure plain text is a multiple of 128 bits
        // TODO: generate auth data (meta data)
        let total_len = plain_text.len() + auth_data.len() + BLOCK_SIZE;
        let mut intermediate_cipher_text: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        let mut concat = vec![0; total_len];
        let mut tag: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

        let iv: [u8; 12] = [0;12];
        let mut increment: u32 = 0;
        
        let ghash_key: [u8; BLOCK_SIZE] = initial_hash_subkey(&self.expanded_key);

        let mut counter_input: [u8; BLOCK_SIZE] = initial_counter_input(&iv, &mut increment);
        increment_counter(&mut counter_input, &mut increment);
        
        gctr(&mut intermediate_cipher_text, &plain_text, &self.expanded_key, &counter_input, &mut increment);

        byte_concatenation(&mut concat, &auth_data, &intermediate_cipher_text, &(auth_data.len() as u32), &(plain_text.len() as u32), &(total_len as u32));

        ghash(cipher_text, &ghash_key, &concat, &(total_len as u32));


        let second_counter_input: [u8; BLOCK_SIZE] = initial_counter_input(&iv, &mut increment);
        gctr(&mut tag, &cipher_text, &self.expanded_key, &second_counter_input, &mut increment);

        println!("Ciphertext: {:?}", cipher_text);
        println!("Tag: {:?}", tag);
    }

    fn decrypt(&self, destination: &mut[u8], cipher_text: &[u8]) {
        let mut state: [u32;4] = [0;4];
        pack(&mut state, &cipher_text[0..BLOCK_SIZE]);
        aes_decrypt(&mut state, &self.expanded_key);
        unpack(&mut destination[0..BLOCK_SIZE], &mut state);
    }
}

fn ghash(output: &mut[u8], hash_subkey: &[u8], data: &[u8], total_len: &u32) {
    let mut y: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    let mut z: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    let mut tmp: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

    for i in 0..(total_len/(BLOCK_SIZE as u32)) as usize {
        for j in 0..BLOCK_SIZE {
            tmp[j] = data[(i * BLOCK_SIZE) + j];
        }

        xor_block(&mut y, &mut tmp);
        galois_field_mul_128(&mut z, hash_subkey, &mut y);
        y.copy_from_slice(&z);
    }

    output.copy_from_slice(&y);
}

fn byte_concatenation(concat: &mut[u8], auth_data: &[u8], cipher_text: &[u8], len_auth_data: &u32, len_plain_text: &u32, total_len: &u32) {
    let mut len_c: [u8; 8] = [0; 8];
    let len_c_in_bits: u32 = len_plain_text * 8;
    
    let mut len_a: [u8; 8] = [0; 8];
    let len_ad_in_bits: u32 = len_auth_data * 8;

    let mut len_concat: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];


    for i in 0..(*len_auth_data / 16) as usize {
        len_a[i] = ((len_ad_in_bits >> 8 * i) & 0xff) as u8;
    }

    for i in 0..(*len_plain_text / 16) as usize {
        len_c[i] = ((len_c_in_bits >> 8 * i) & 0xff) as u8;
    }

    for n in (0..16).rev() {
        if n > 7 {
            len_concat[n] = len_c[7-n % 8];
        } else {
            len_concat[n] = len_a[7-n % 8];
        }
    }

    for i in 0..(*total_len as usize) {
        let comparable_index = i as u32;
        if comparable_index < *len_auth_data {
            concat[i] = auth_data[i];
        } else if (comparable_index >= *len_auth_data) && (comparable_index < len_auth_data + len_plain_text) {
            concat[i] = cipher_text[((comparable_index - len_auth_data) % len_plain_text) as usize];
        } else {
            concat[i] = len_concat[i % BLOCK_SIZE];
        }
    }
}

fn gctr(cipher_text: &mut[u8], plain_text: &[u8], expanded_key: &[u32], counter_block: &[u8], increment: &mut u32) {

    let mut state: [u32;4] = [0;4];

    let length_128_bit_blocks = plain_text.len() / 16;

    let mut local_counter_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    local_counter_block.copy_from_slice(counter_block);

    let mut last_encryption_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

    for i in 0..length_128_bit_blocks {
        pack(&mut state, &local_counter_block[0..BLOCK_SIZE]);
        aes_encrypt(&mut state, &expanded_key);
        unpack(&mut last_encryption_block[0..BLOCK_SIZE], &mut state);

        for j in 0..BLOCK_SIZE{
            cipher_text[(i*BLOCK_SIZE) + j] = plain_text[(i*BLOCK_SIZE) + j] ^ last_encryption_block[j];
        }
        increment_counter(&mut local_counter_block, increment);
    }
}

fn galois_field_mul_128(output: &mut [u8], hash_subkey: &[u8], y: &mut [u8]) {
    let mut tmp: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE]; 
    tmp.copy_from_slice(y);

    for i in 0..BLOCK_SIZE {
        for j in 0..(BLOCK_SIZE/2) {
            if (hash_subkey[i] & PWR_X_GALOIS_FIELD[7-j]) != 0 {
                xor_block(output, &mut tmp);
            }
            if (tmp[15] & 0x01) == 0x01 {
                shift_right(&mut tmp);
                tmp[0] ^= 0xe1;
            } else {
                shift_right(&mut tmp);
            }
        }
    }
}

fn shift_right(output: &mut [u8]) {
    let mut prev_carry: u8;
    let mut current_carry: u8 = 0;

    for i in 0..BLOCK_SIZE{
        prev_carry = current_carry;

        if (output[i] & 0x01) == 1 {
            current_carry = 0x80;
        } else {
            current_carry = 0x00;
        }

        output[i] >>= 0x01;
        output[i] += prev_carry;
    }
}

fn xor_block(output: &mut [u8], tmp: &mut [u8]) {
    for i in 0..BLOCK_SIZE {
        output[i] ^= tmp[i];
    }
}

fn increment_counter(counter: &mut [u8], increment: &mut u32) {
    
    *increment = (*increment) + 1;
    
    for i in 0..4 {
        counter[BLOCK_SIZE-1-i] = (*increment >> 8 * i & 0xff) as u8;
    }
}

fn initial_counter_input(iv: &[u8], increment: &mut u32) -> [u8; BLOCK_SIZE]{
    
    *increment = 1;
    
    let mut counter: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    for i in 0..iv.len(){
        counter[i] = iv[i];
    }
    counter[BLOCK_SIZE-1] = *increment as u8;
    return counter;
}

fn initial_hash_subkey(expanded_key: &[u32]) -> [u8; BLOCK_SIZE]{
    let mut state: [u32;4] = [0;4];
    let mut ghash_key: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    
    pack(&mut state, &ghash_key);
    aes_encrypt(&mut state, &expanded_key);
    unpack(&mut ghash_key, &mut state);

    return ghash_key;
}

// UNIT TESTING

#[cfg(test)]
mod tests {
    use rand::Rng;
    use super::*;

    #[test]
    fn test_initial_hash_subkey() {
        let key = "PURPLE SIDEKICKS";
        let expkey = key_expansion(key.as_bytes());
        
        let mut state: [u32; 4] = [0; 4];
        let mut output = initial_hash_subkey(&expkey);
        
        pack(&mut state, &output);
        aes_decrypt(&mut state, &expkey);
        unpack(&mut output, &mut state);

        for j in 0..output.len() {
            assert_eq!(output[j], 0x00, "Expected {} but got {}", 0x00, output[j]);
        }
    }

    #[test]
    fn test_initial_counter_block() {
        let iv: [u8; 12] = [0x57, 0xe4, 0x12, 0x27, 0x1d, 0x8a, 0xe7, 0x96, 0x8b, 0x6f, 0xfd, 0x38 ];
        let mut increment :u32 = 0;
        let mut state: [u32; 4] = [0; 4];
        
        let mut output = initial_counter_input(&iv, &mut increment);

        for i in 0..12 {
            assert_eq!(output[i], iv[i], "Expected {} but got {}", iv[i], output[i]);
        }
        for i in 12..15 {
            assert_eq!(output[i], 0x00, "Expected {} but got {}", 0x00, output[i]);
        }
        assert_eq!(output[15], 0x01, "Expected {} but got {}", 0x01, output[15]);
    }

    #[test]
    fn test_increment_counter() {
        let iv: [u8; 12] = [0x57, 0xe4, 0x12, 0x27, 0x1d, 0x8a, 0xe7, 0x96, 0x8b, 0x6f, 0xfd, 0x38 ];
        let mut increment :u32 = 0;
        let mut state: [u32; 4] = [0; 4];
        
        let mut output = initial_counter_input(&iv, &mut increment);
        increment_counter(&mut output, &mut increment);

        for i in 0..12 {
            assert_eq!(output[i], iv[i], "Expected {} but got {}", iv[i], output[i]);
        }
        for i in 12..15 {
            assert_eq!(output[i], 0x00, "Expected {} but got {}", 0x00, output[i]);
        }
        assert_eq!(output[15], 0x02, "Expected {} but got {}", 0x02, output[15]);
    }
}

