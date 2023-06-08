

// Generates an 128 bits AES Key
fn generateAESKey() {

}

fn add_round_key(state: &mut [u32], key: &[u32]) {
    for i in 0..4 {
        // bitwise xor
        state[i] = state[i] ^ key[i]
    }
}


// TODO: Understande this code
// TODO: Implement sbox
// fn sub_word(input: u32){
//     return ((sbox[input>>24])<<24) as u32 |
// 		((sbox[input>>16&0xff])<<16) as u32 |
// 		((sbox[input>>8&0xff])<<8) as u32 |
// 		((sbox[input&0xff])) as u32;
// }

fn sub_bytes(state: &mut [u32]) {
    for i in 0..state.len(){
        // state[i] = sub_word(state[i]);
    }
}

/// Rotates the word n bytes to the left.
fn rotate_word_left(input: u32, n: usize) -> u32{
    return input >> (32-8*n) | input << (8*n)
}

fn shift_rows(state: &mut [u32]) {
    for i in 1..4 {
        // rotate word left by specified number of bytes
		state[i] = rotate_word_left(state[i], i)
    }
}

/// TODO: Understand this code
/// TODO: Implement Galois Field Multiplication
fn calc_new_bytes(column_bytes: &[u8; 4])-> [u8; 4] {
    let mut new_bytes: [u8; 4] = [0; 4];
    new_bytes[0] = (galois_mul2.get(column_bytes[0]) ^ galois_mul3.get(column_bytes[1]) ^ column_bytes[2] ^ column_bytes[3]) as u8;
    new_bytes[1] = (column_bytes[0] ^ galois_mul2.get(column_bytes[1]) ^ galois_mul3.get(column_bytes[2]) ^ column_bytes[3]) as u8;
    new_bytes[2] = (column_bytes[0] ^ column_bytes[1] ^ galois_mul2.get(column_bytes[2]) ^ galois_mul3.get(column_bytes[3])) as u8;
    new_bytes[3] = (galois_mul3.get(column_bytes[0]) ^ column_bytes[1] ^ column_bytes[2] ^ galois_mul2.get(column_bytes[3])) as u8;
    return new_bytes;
}

/// based on https://en.wikipedia.org/wiki/Rijndael_mix_columns#MixColumns
/// a0-3 represent the bytes of a column
/// r0-3 are the transformed bytes
fn mix_columns(state: &mut [u32]) {
    for i in 0..4 {
        /// TODO: Understand this code
        let mut column_bytes: [u8; 4] = [0; 4];
        column_bytes[0] = ((state[0] >> ((3 - i) * 8)) & 0xff) as u8;
		column_bytes[1] = ((state[1] >> ((3 - i) * 8)) & 0xff) as u8;
		column_bytes[2] = ((state[2] >> ((3 - i) * 8)) & 0xff) as u8;
		column_bytes[3] = ((state[3] >> ((3 - i) * 8)) & 0xff) as u8;

        let mut new_bytes: [u8; 4] = calc_new_bytes(&column_bytes);

        // TODO: Undestand this code
        let mut mask: uint32
		mask = 0xff << ((3 - i) * 8)
		mask = mask^mask

        // Set new values
		state[0] = (state[0] & mask) | ((new_bytes[0] as u32) << ((3 - i) * 8))
		state[1] = (state[1] & mask) | ((new_bytes[1] as u32) << ((3 - i) * 8))
		state[2] = (state[2] & mask) | ((new_bytes[2] as u32) << ((3 - i) * 8))
		state[3] = (state[3] & mask) | ((new_bytes[3] as u32) << ((3 - i) * 8))
    }
}

fn inv_mix_columns(){

}

fn inv_shift_rows() {

}

// TODO: Understand this code
// fn inv_sub_word(input u32) {
//     return ((sbox_inverse[input>>24])<<24) as u32 |
// 		((sbox_inverse[input>>16&0xff])<<16) as u32 |
// 		((sbox_inverse[input>>8&0xff])<<8) as u32 |
// 		(sbox_inverse[input&0xff]) as u32;
// }

fn inv_sub_bytes(state: &mut [u32]) {
    for i in 0..state.len() {
		// state[i] = inv_sub_word(state[i])
	}
}


/// The 16-byte block, called state is represented as a slice of 
/// 4 4-byte unsigned integers. 
/// The expanded key is based on the original key. Its 16*(rounds+1) bytes in 
/// length.
fn encrypt(state: &mut [u32], expanded_key: &[u32], rounds: u8) {
    let mut key_index = 0;
    add_round_key(state, &expanded_key[key_index .. key_index+4]);
    key_index = key_index + 4;
    
    for i in 0..rounds {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &expanded_key[key_index .. key_index+4]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &expanded_key[key_index .. key_index+4])
}