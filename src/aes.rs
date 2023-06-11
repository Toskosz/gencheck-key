use crate::utils::*;

pub struct AES {
    expanded_key: [u32; 44]
}

impl AES {
    fn new(key: &[u8]) -> AES {
        AES {
            expanded_key: key_expansion(key)
        }
    }

    fn encrypt(&self, destination: &mut[u8], plain_text: &[u8]) {  
        let mut state: [u32;4] = [0;4];
        pack(&mut state, &plain_text[0..BLOCK_SIZE]);
        encrypt(&mut state, &self.expanded_key);
        unpack(&mut destination[0..BLOCK_SIZE], &mut state);
    }

    fn decrypt(&self, destination: &mut[u8], cipher_text: &[u8]) {
        let mut state: [u32;4] = [0;4];
        pack(&mut state, &cipher_text[0..BLOCK_SIZE]);
        decrypt(&mut state, &self.expanded_key);
        unpack(&mut destination[0..BLOCK_SIZE], &mut state);
    }
}

// The 16-byte block, called state is represented as a slice of 
// 4 4-byte unsigned integers. 
// The expanded key is based on the original key. Its 16*(rounds+1) bytes in 
// length.
fn encrypt(state: &mut [u32], expanded_key: &[u32]) {
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

fn decrypt(state: &mut [u32], expanded_key: &[u32]) {
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

// Based on https://en.wikipedia.org/wiki/Rijndael_key_schedule
// Expands the original key to get the round keys
fn key_expansion(key: &[u8]) -> [u32;44] {
    // These values come from the AES standard for 128 bit keys.
    const n_words: usize = 4;
    const rounds: usize = 10;
    let mut expanded_key: [u32;4*(rounds+1)] = [0;4*(rounds+1)];
    
    // Each round requires a 4 word key. So we need 4(10+1) words in the expanded key
    
    let mut i = 0;
    // First 4 words are the original key
    for i in 0..n_words {
        expanded_key[i] = ((key[4*i] as u32) << 24) | ((key[4*i+1] as u32) << 16) | ((key[4*i+2] as u32) << 8) | (key[4*i+3] as u32);
    }

    while i < 4*(rounds+1) {
        expanded_key[i] = expanded_key[i-1];
        expanded_key[i] = rotate_word_left(expanded_key[i], 1);
        expanded_key[i] = sub_word(expanded_key[i]);
        expanded_key[i] = expanded_key[i] ^ get_round_constant((i/n_words)-1);
        expanded_key[i] = expanded_key[i] ^ expanded_key[i-n_words];

        for j in 1..4 {
            expanded_key[i+j] = expanded_key[i+j-1] ^ expanded_key[i+j-n_words];
        }

        i = i + n_words;
    }

    for j in (0..expanded_key.len()).step_by(4) {
        transpose(&mut expanded_key[j..j+4])
    }

    return expanded_key;
}

// Generates an 128 bits AES Key
fn generate_aes_key() {

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

// Breaks the input into 4 bytes
// Substitutes each byte for the corresponding value in the SBOX
// Joins the substituted bytes into a 32 bit word through bitwise or
fn sub_word(input: u32) -> u32{
    return ((SBOX[(input>>24) as usize])<<24) as u32 |
		((SBOX[(input>>16&0xff) as usize])<<16) as u32 |
		((SBOX[(input>>8&0xff) as usize])<<8) as u32 |
		((SBOX[(input&0xff) as usize])) as u32;
}

// Substitutes each byte-row in the state matrix for the corresponding value in 
// the SBOX
fn sub_bytes(state: &mut [u32]) {
    for i in 0..state.len(){
        state[i] = sub_word(state[i]);
    }
}

// Breaks the input into 4 bytes
// Substitutes each byte for the corresponding value in the reverse SBOX
// Joins the substituted bytes into a 32 bit word through bitwise or
fn revert_sub_word(input: u32) -> u32{
    return ((SBOX_INVERSE[(input>>24) as usize])<<24) as u32 |
		((SBOX_INVERSE[(input>>16&0xff) as usize])<<16) as u32 |
		((SBOX_INVERSE[(input>>8&0xff) as usize])<<8) as u32 |
		(SBOX_INVERSE[(input&0xff) as usize]) as u32;
}

// Substitutes each byte-row in the state matrix for the corresponding value in 
// the reverse-SBOX
fn revert_sub_bytes(state: &mut [u32]) {
    for i in 0..state.len() {
		state[i] = revert_sub_word(state[i])
	}
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

        // Used to clear the row from its existing value
        let mut mask: u32;
		mask = 0xff << ((3 - i) * 8);
		mask = mask^mask;

        // Set new values
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
