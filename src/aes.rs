use crate::utils::*;

// Generates an 128 bits AES Key
fn generate_aes_key() {

}

fn add_round_key(state: &mut [u32], key: &[u32]) {
    for i in 0..4 {
        // bitwise xor
        state[i] = state[i] ^ key[i]
    }
}


// TODO: Understand this code
fn sub_word(input: u32) -> u32{
    return ((SBOX[(input>>24) as usize])<<24) as u32 |
		((SBOX[(input>>16&0xff) as usize])<<16) as u32 |
		((SBOX[(input>>8&0xff) as usize])<<8) as u32 |
		((SBOX[(input&0xff) as usize])) as u32;
}

fn sub_bytes(state: &mut [u32]) {
    for i in 0..state.len(){
        state[i] = sub_word(state[i]);
    }
}

// Rotates the word n bytes to the left.
fn rotate_word_left(input: u32, n: usize) -> u32{
    return input >> (32-8*n) | input << (8*n)
}

fn shift_rows(state: &mut [u32]) {
    for i in 1..4 {
        // rotate word left by specified number of bytes
		state[i] = rotate_word_left(state[i], i)
    }
}

// TODO: Understand this code
fn calc_new_bytes(column_bytes: &[u8; 4])-> [u8; 4] {
    let mut new_bytes: [u8; 4] = [0; 4];
    new_bytes[0] = (GALOIS_MUL2[column_bytes[0] as usize] ^ GALOIS_MUL3[column_bytes[1] as usize] ^ column_bytes[2] ^ column_bytes[3]) as u8;
    new_bytes[1] = (column_bytes[0] ^ GALOIS_MUL2[column_bytes[1] as usize] ^ GALOIS_MUL3[column_bytes[2] as usize] ^ column_bytes[3]) as u8;
    new_bytes[2] = (column_bytes[0] ^ column_bytes[1] ^ GALOIS_MUL2[column_bytes[2] as usize] ^ GALOIS_MUL3[column_bytes[3] as usize]) as u8;
    new_bytes[3] = (GALOIS_MUL3[column_bytes[0] as usize] ^ column_bytes[1] ^ column_bytes[2] ^ GALOIS_MUL2[column_bytes[3] as usize]) as u8;
    return new_bytes;
}

// TODO: Understande this code
fn revert_calc_new_bytes(column_bytes: &[u8; 4])-> [u8; 4] {
    let mut new_bytes: [u8; 4] = [0; 4];
    new_bytes[0] = GALOIS_MUL14[column_bytes[0] as usize] ^ GALOIS_MUL11[column_bytes[1] as usize] ^ GALOIS_MUL13[column_bytes[2] as usize] ^ GALOIS_MUL9[column_bytes[3] as usize];
    new_bytes[1] = GALOIS_MUL9[column_bytes[0] as usize] ^GALOIS_MUL14[column_bytes[1] as usize] ^ GALOIS_MUL11[column_bytes[2] as usize] ^ GALOIS_MUL13[column_bytes[3] as usize];
    new_bytes[2] = GALOIS_MUL13[column_bytes[0] as usize] ^ GALOIS_MUL9[column_bytes[1] as usize] ^ GALOIS_MUL14[column_bytes[2] as usize] ^ GALOIS_MUL11[column_bytes[3] as usize];
    new_bytes[3] = GALOIS_MUL11[column_bytes[0] as usize] ^ GALOIS_MUL13[column_bytes[1] as usize] ^ GALOIS_MUL9[column_bytes[2] as usize] ^ GALOIS_MUL14[column_bytes[3] as usize];
    return new_bytes;
}

// based on https://en.wikipedia.org/wiki/Rijndael_mix_columns#MixColumns
fn manipulate_columns(state: &mut [u32], revert: bool) {
    let mut new_bytes: [u8; 4];
    let mut column_bytes: [u8; 4] = [0; 4];
    for i in 0..4 {
        // TODO: Understand this code
        column_bytes[0] = ((state[0] >> ((3 - i) * 8)) & 0xff) as u8;
		column_bytes[1] = ((state[1] >> ((3 - i) * 8)) & 0xff) as u8;
		column_bytes[2] = ((state[2] >> ((3 - i) * 8)) & 0xff) as u8;
		column_bytes[3] = ((state[3] >> ((3 - i) * 8)) & 0xff) as u8;

        if revert{
            new_bytes = revert_calc_new_bytes(&column_bytes);
        } else {
            new_bytes = calc_new_bytes(&column_bytes);
        }

        // TODO: Undestand this code
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

fn inv_shift_rows() {

}

// TODO: Understand this code
fn inv_sub_word(input: u32) -> u32{
    return ((SBOX_INVERSE[(input>>24) as usize])<<24) as u32 |
		((SBOX_INVERSE[(input>>16&0xff) as usize])<<16) as u32 |
		((SBOX_INVERSE[(input>>8&0xff) as usize])<<8) as u32 |
		(SBOX_INVERSE[(input&0xff) as usize]) as u32;
}

fn inv_sub_bytes(state: &mut [u32]) {
    for i in 0..state.len() {
		state[i] = inv_sub_word(state[i])
	}
}


// The 16-byte block, called state is represented as a slice of 
// 4 4-byte unsigned integers. 
// The expanded key is based on the original key. Its 16*(rounds+1) bytes in 
// length.
fn encrypt(state: &mut [u32], expanded_key: &[u32], rounds: u8) {
    let mut key_index = 0;
    add_round_key(state, &expanded_key[key_index .. key_index+4]);
    key_index = key_index + 4;
    
    for _ in 0..rounds {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &expanded_key[key_index .. key_index+4]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &expanded_key[key_index .. key_index+4])
}