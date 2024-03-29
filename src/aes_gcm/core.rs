// mod utils;
use crate::aes_gcm::utils::*;

pub fn pad_to_128(data: &mut Vec<u8>){
    while data.len() % 16 != 0 {
        data.push(0x00);
    }
}

pub fn generate_128bit_key() -> [u8;16] {
    let mut key: [u8;16] = [0;16];
    insert_random_bytes(&mut key).expect("Failed to generate random bytes");
    return key;
}

// Based on https://en.wikipedia.org/wiki/Rijndael_key_schedule
// Expands the original key to get the round keys
pub fn key_expansion(key: &[u8]) -> [u32;44] {
    // These values come from the AES standard for 128 bit keys.
    const N_WORDS: usize = 4;
    const ROUNDS: usize = 10;
    let mut expanded_key: [u32;4*(ROUNDS+1)] = [0;4*(ROUNDS+1)];
    
    // Each round requires a 4 word key. So we need 4(10+1) words in the expanded key
    
    let mut i = 0;
    // First 4 words are the original key
    while i < N_WORDS {
        expanded_key[i] = ((key[4*i] as u32) << 24) | ((key[4*i+1] as u32) << 16) | ((key[4*i+2] as u32) << 8) | (key[4*i+3] as u32);
        i += 1;
    }

    while i < 4*(ROUNDS+1) {
        expanded_key[i] = expanded_key[i-1];
        expanded_key[i] = rotate_word_left(expanded_key[i], 1);
        expanded_key[i] = sub_word(expanded_key[i]);
        expanded_key[i] = expanded_key[i] ^ get_round_constant((i/N_WORDS)-1);
        expanded_key[i] = expanded_key[i] ^ expanded_key[i-N_WORDS];

        for j in 1..4 {
            expanded_key[i+j] = expanded_key[i+j-1] ^ expanded_key[i+j-N_WORDS];
        }

        i = i + N_WORDS;
    }

    for j in (0..expanded_key.len()).step_by(4) {
        transpose(&mut expanded_key[j..j+4])
    }

    return expanded_key;
}

// Bitwise XOR between the state and the key
fn add_round_key(state: &mut [u32], key: &[u32]) {
    for i in 0..4 {
        // bitwise xor
        state[i] = state[i] ^ key[i]
    }
}

// Get round constant according to rijndael's specification
fn get_round_constant(round: usize) -> u32 {
    return ((PWR_X_GALOIS_FIELD[round]) as u32) << 24
}

fn transpose(input: &mut[u32]) {
    let mut c0: u32 = 0;
    let mut c1: u32 = 0;
    let mut c2: u32 = 0;
    let mut c3: u32 = 0;

    for i in 0..4 {
        c0 = c0 | (input[i] >> 24)        << (8 * (3 - i));
        c1 = c1 | (input[i] >> 16 & 0xff) << (8 * (3 - i));
        c2 = c2 | (input[i] >> 8  & 0xff) << (8 * (3 - i));
        c3 = c3 | (input[i]       & 0xff) << (8 * (3 - i));
    }

    input[0] = c0;
    input[1] = c1;
    input[2] = c2;
    input[3] = c3;
}

// Substitutes each byte-row in the state matrix for the corresponding value in 
// the SBOX
fn sub_bytes(state: &mut [u32]) {
    for i in 0..state.len(){
        state[i] = sub_word(state[i]);
    }
}

// Substitutes each byte-row in the state matrix for the corresponding value in 
// the reverse-SBOX
fn revert_sub_bytes(state: &mut [u32]) {
    for i in 0..state.len() {
        state[i] = revert_sub_word(state[i])
    }
}

// Breaks the input into 4 bytes
// Substitutes each byte for the corresponding value in the SBOX
// Joins the substituted bytes into a 32 bit word through bitwise or
fn sub_word(input: u32) -> u32{
    return ((SBOX[(input>>24) as usize] as u32) << 24) |
		((SBOX[(input>>16&0xff) as usize] as u32) << 16) |
		((SBOX[(input>>8&0xff) as usize] as u32) <<8) |
		((SBOX[(input&0xff) as usize] as u32));
}

// Breaks the input into 4 bytes
// Substitutes each byte for the corresponding value in the reverse SBOX
// Joins the substituted bytes into a 32 bit word through bitwise or
fn revert_sub_word(input: u32) -> u32{
    return ((SBOX_INVERSE[(input>>24) as usize] as u32)<<24) |
		((SBOX_INVERSE[(input>>16&0xff) as usize] as u32)<<16) |
		((SBOX_INVERSE[(input>>8&0xff) as usize] as u32)<<8) |
		(SBOX_INVERSE[(input&0xff) as usize]) as u32;
}

// Rotates the word n bytes to the left.
fn rotate_word_left(input: u32, n: usize) -> u32{
    return input >> (32-8*n) | input << (8*n)
}

// Rotates the word n bytes to the right.
fn rotate_word_right(input: u32, n: usize) -> u32{
    return input << (32-8*n) | input >> (8*n)
}

// Shift every row, except the first one, from the state matrix to the left
fn shift_rows(state: &mut [u32]) {
    for i in 1..4 {
		state[i] = rotate_word_left(state[i], i)
    }
}

// Reverts the shift operation by shifting every row, except the first one, from
// the state matrix to the right
fn revert_shift_rows(state: &mut [u32]) {
    for i in 1..4 {
        state[i] = rotate_word_right(state[i], i);
    }
}

// Read https://en.wikipedia.org/wiki/Rijndael_mix_columns#MixColumns
fn calc_new_bytes(column_bytes: &[u8; 4])-> [u8; 4] {
    let mut new_bytes: [u8; 4] = [0; 4];
    new_bytes[0] = (GALOIS_MUL2[column_bytes[0] as usize] ^ GALOIS_MUL3[column_bytes[1] as usize] ^ column_bytes[2] ^ column_bytes[3]) as u8;
    new_bytes[1] = (column_bytes[0] ^ GALOIS_MUL2[column_bytes[1] as usize] ^ GALOIS_MUL3[column_bytes[2] as usize] ^ column_bytes[3]) as u8;
    new_bytes[2] = (column_bytes[0] ^ column_bytes[1] ^ GALOIS_MUL2[column_bytes[2] as usize] ^ GALOIS_MUL3[column_bytes[3] as usize]) as u8;
    new_bytes[3] = (GALOIS_MUL3[column_bytes[0] as usize] ^ column_bytes[1] ^ column_bytes[2] ^ GALOIS_MUL2[column_bytes[3] as usize]) as u8;
    return new_bytes;
}

// Read https://en.wikipedia.org/wiki/Rijndael_mix_columns#MixColumns
fn revert_calc_new_bytes(column_bytes: &[u8; 4])-> [u8; 4] {
    let mut new_bytes: [u8; 4] = [0; 4];
    new_bytes[0] = GALOIS_MUL14[column_bytes[0] as usize] ^ GALOIS_MUL11[column_bytes[1] as usize] ^ GALOIS_MUL13[column_bytes[2] as usize] ^ GALOIS_MUL9[column_bytes[3] as usize];
    new_bytes[1] = GALOIS_MUL9[column_bytes[0] as usize] ^GALOIS_MUL14[column_bytes[1] as usize] ^ GALOIS_MUL11[column_bytes[2] as usize] ^ GALOIS_MUL13[column_bytes[3] as usize];
    new_bytes[2] = GALOIS_MUL13[column_bytes[0] as usize] ^ GALOIS_MUL9[column_bytes[1] as usize] ^ GALOIS_MUL14[column_bytes[2] as usize] ^ GALOIS_MUL11[column_bytes[3] as usize];
    new_bytes[3] = GALOIS_MUL11[column_bytes[0] as usize] ^ GALOIS_MUL13[column_bytes[1] as usize] ^ GALOIS_MUL9[column_bytes[2] as usize] ^ GALOIS_MUL14[column_bytes[3] as usize];
    return new_bytes;
}

// Multiplication and addition in the Galois field.
// Each byte of the column is replaced based on an operation.
fn manipulate_columns(state: &mut [u32], revert: bool) {
    let mut new_bytes: [u8; 4];
    let mut column_bytes: [u8; 4] = [0; 4];
    for i in 0..4 {
        // Gets the byte at ((3-i)*8) position of each word in the state matrix
        // to form a column     
        column_bytes[0] = ((state[0] >> ((3 - i) * 8)) & 0xff) as u8;
		column_bytes[1] = ((state[1] >> ((3 - i) * 8)) & 0xff) as u8;
		column_bytes[2] = ((state[2] >> ((3 - i) * 8)) & 0xff) as u8;
		column_bytes[3] = ((state[3] >> ((3 - i) * 8)) & 0xff) as u8;

        if revert{
            new_bytes = revert_calc_new_bytes(&column_bytes);
        } else {
            new_bytes = calc_new_bytes(&column_bytes);
        }

        // remove old value 
        let mut mask: u32;
		mask = 0xff << ((3 - i) * 8);
        mask = !mask;

        // add new values
		state[0] = (state[0] & mask) | ((new_bytes[0] as u32) << ((3 - i) * 8));
		state[1] = (state[1] & mask) | ((new_bytes[1] as u32) << ((3 - i) * 8));
		state[2] = (state[2] & mask) | ((new_bytes[2] as u32) << ((3 - i) * 8));
		state[3] = (state[3] & mask) | ((new_bytes[3] as u32) << ((3 - i) * 8));
    }
}

fn mix_columns(state: &mut [u32]){
    manipulate_columns(state, false);
}

fn revert_mix_columns(state: &mut [u32]){
    manipulate_columns(state, true);
}

// The 16-byte block, called state is represented as a slice of 
// 4 4-byte unsigned integers. 
// The expanded key is based on the original key. Its 16*(rounds+1) bytes in 
// length.
pub fn aes_encrypt(state: &mut [u32], expanded_key: &[u32]) {
    let mut key_index = 0;
    add_round_key(state, &expanded_key[key_index .. key_index+4]);
    key_index = key_index + 4;
    
    for _ in 0..((expanded_key.len()/4)-2) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &expanded_key[key_index .. key_index+4]);
        key_index = key_index + 4;
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &expanded_key[key_index .. key_index+4])
}

pub fn aes_decrypt(state: &mut [u32], expanded_key: &[u32]) {
    let mut key_index = expanded_key.len() - 4;
    add_round_key(state, &expanded_key[key_index .. key_index+4]);
    key_index = key_index - 4;
    
    for _ in 0..(expanded_key.len()/4-2) {
        revert_shift_rows(state);
        revert_sub_bytes(state);
        add_round_key(state, &expanded_key[key_index .. key_index+4]);
        key_index = key_index - 4;
        revert_mix_columns(state);
    }
    revert_shift_rows(state);
    revert_sub_bytes(state);
    add_round_key(state, &expanded_key[key_index .. key_index+4])
}

pub fn core_encrypt(plain_text: &mut Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let expkey = key_expansion(key);
    pad_to_128(plain_text);
    let mut cipher_text: Vec<u8> = vec![];
    
    // intermediary variables
    let mut state: [u32; 4] = [0; 4];
    let mut tmp: [u8; 16] = [0; 16];
    
    for slice in plain_text.chunks(16) {
        pack(&mut state, &slice);
        aes_encrypt(&mut state, &expkey);
        unpack(&mut tmp, &mut state);

        for j in 0..16 {
            cipher_text.push(tmp[j]);
        }
    }

    return cipher_text;
}

// A "correct" cipher text is always of size multiple of 128 bits.
pub fn core_decrypt(cipher_text: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let expkey = key_expansion(key);
    let mut plain_text: Vec<u8> = vec![];
    
    // intermediary variables
    let mut state: [u32; 4] = [0; 4];
    let mut tmp: [u8; 16] = [0; 16];
    
    for slice in cipher_text.chunks(16) {
        pack(&mut state, &slice);
        aes_decrypt(&mut state, &expkey);
        unpack(&mut tmp, &mut state);

        for j in 0..16 {
            plain_text.push(tmp[j]);
        }
    }

    return plain_text;
}

// UNIT TESTING

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_expansion() {
        let key = "YELLOW SUBMARINE";

        let expanded_key: [u32; 44] = [
            0x594f5552, 0x45574249, 0x4c204d4e, 0x4c534145, 0x632c792b,
            0x6a3d7f36, 0x22024f01, 0x4c1f5e1b, 0x6448311a, 0x162b5462, 0x8d8fc0c1, 0xbda2fce7,
            0xca82b3a9, 0x6e451173, 0x19965697, 0x1fbd41a6, 0x4dcf7cd5, 0xe6a3b2c1, 0x3dabfd6a,
            0xcc713096, 0x25ea9643, 0xe447f534, 0xad06fb91, 0xcfbe8e18, 0x1df76122, 0x6522d7e3,
            0x6fd6c, 0xd56be5fd, 0x4cbbdaf8, 0x3517c023, 0x5452afc3, 0x462dc835, 0xea518b73,
            0x1b0cccef, 0xc2903ffc, 0x72ae2d7, 0x2e7ff487, 0xaba76b84, 0xcc5c639f, 0x88a24097,
            0x4738cc4b, 0x70d7bc38, 0x44187be4, 0x9f3d7dea
        ];

        let actual = key_expansion(key.as_bytes());
        assert!(actual.iter().zip(expanded_key.iter()).all(|(a,b)| a == b), "Arrays are not equal");
    }


    #[test]
    fn test_mix_cols() {
        let mut input: [u32; 4] = [0xdbf201c6, 0x130a01c6, 0x532201c6, 0x455c01c6];
        let expected: [u32; 4] = [0x8e9f01c6, 0x4ddc01c6, 0xa15801c6, 0xbc9d01c6];
        
        mix_columns(&mut input);
        for j in 0..input.len() {
            assert_eq!(input[j], expected[j], "Expected {} but got {}", expected[j], input[j]);
        }
    }


    #[test]
    fn test_revert_mix_cols(){
        let mut input: [u32;4] = [0x8e9f01c6, 0x4ddc01c6, 0xa15801c6, 0xbc9d01c6];
	    let expected: [u32;4] = [0xdbf201c6, 0x130a01c6, 0x532201c6, 0x455c01c6];

        revert_mix_columns(&mut input);
        for j in 0..input.len() {
            assert_eq!(input[j], expected[j], "Expected {} but got {}", expected[j], input[j]);
        }
    }

    #[test]
    fn test_shift_rows(){
        let mut input: [u32;4] = [0x8e9f01c6, 0x4ddc01c6, 0xa15801c6, 0xbc9d01c6];
	    let expected: [u32;4] = [0x8e9f01c6, 0xdc01c64d, 0x01c6a158, 0xc6bc9d01];

        shift_rows(&mut input);
        for j in 0..input.len() {
            assert_eq!(input[j], expected[j], "Expected {} but got {}", expected[j], input[j]);
        }
    }

    #[test]
    fn test_revert_shift_rows(){
        let mut input: [u32;4] = [0x8e9f01c6, 0x4ddc01c6, 0xa15801c6, 0xbc9d01c6];
	    let expected: [u32;4] = [0x8e9f01c6, 0xc64ddc01, 0x01c6a158, 0x9d01c6bc];

        revert_shift_rows(&mut input);
        for j in 0..input.len() {
            assert_eq!(input[j], expected[j], "Expected {} but got {}", expected[j], input[j]);
        }
    }

    #[test]
    fn test_sub_bytes(){
        let mut input: [u32; 4] = [0x8e9ff1c6, 0x4ddce1c7, 0xa158d1c8, 0xbc9dc1c9];
	    let expected: [u32; 4] = [0x19dba1b4, 0xe386f8c6, 0x326a3ee8, 0x655e78dd];

        sub_bytes(&mut input);
        for j in 0..input.len() {
            assert_eq!(input[j], expected[j], "Expected {} but got {}", expected[j], input[j]);
        }
    }

    #[test]
    fn test_revert_sub_bytes(){
        let mut input: [u32;4] = [0x19dba1b4, 0xe386f8c6, 0x326a3ee8, 0x655e78dd];
	    let expected: [u32;4] = [0x8e9ff1c6, 0x4ddce1c7, 0xa158d1c8, 0xbc9dc1c9];

        revert_sub_bytes(&mut input);
        for j in 0..input.len() {
            assert_eq!(input[j], expected[j], "Expected {} but got {}", expected[j], input[j]);
        }
    }

    #[test]
    fn test_transpose(){
        let mut input: [u32;4] = [0x8e9f01c6, 0x4ddc01c6, 0xa15801c6, 0xbc9d01c6];
	    let expected: [u32;4] = [0x8e4da1bc, 0x9fdc589d, 0x01010101, 0xc6c6c6c6];

        transpose(&mut input);
        for j in 0..input.len() {
            assert_eq!(input[j], expected[j], "Expected {} but got {}", expected[j], input[j]);
        }
    }

    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = "PURPLE SIDEKICKS";
        let expkey = key_expansion(key.as_bytes());
        
        let mut input: [u32; 4] = [0; 4];
        let mut expected: [u32; 4] = [0; 4];
        let b = "polar bears rock!".as_bytes();
        for _ in 0..10 {
            // b = rand::thread_rng().gen::<[u8; 16]>();
            pack(&mut input, &b);
            pack(&mut expected, &b);

            aes_encrypt(&mut input, &expkey);
            aes_decrypt(&mut input, &expkey);
            for j in 0..input.len() {
                if input[j] != expected[j] {
                    assert_eq!(input[j], expected[j], "Expected {} but got {}", input[j], expected[j]);
                }
            }
        }
    }
}
