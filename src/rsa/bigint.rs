use std::fmt;
use std::ops::{
    Add, Sub, Mul, Div, Rem, Shl, Shr,
    AddAssign, SubAssign, MulAssign,
    DivAssign, RemAssign, ShlAssign, ShrAssign,
};
use std::cmp::Ordering;
use crate::rsa::utils::insert_random_bytes;

const N: usize = 1024 / 64;

#[derive(Clone, Copy)]
pub struct BigInt {
    pub chunks: [u64; N],
}

impl BigInt {
    pub fn zero() -> Self {
        return Self { chunks: [0; N] }
    }

    pub fn is_zero(&self) -> bool {
        return self.chunks == [0; N]
    }

    pub fn is_even(&self) -> bool {
        return self.chunks[0] & 1 == 0
    }

    pub fn random() -> Self {
        let mut bytes = [0; 512 / 8];
        insert_random_bytes(&mut bytes).expect("Failed to generate random bytes");
        return Self::from(bytes.as_slice());
    }

    pub fn modify(&mut self) {
        self.chunks[(N / 2) - 1] = self.chunks[(N / 2) - 1] | (0x8000000000000000) as u64;
        self.chunks[0] = self.chunks[0] | 1; 
    }
}

impl From<u128> for BigInt {
    fn from(num: u128) -> Self {
        let mut chunks = [0; N];
        chunks[0] = num as u64;
        chunks[1] = (num >> 64) as u64;
        return Self { chunks };
    }
}

impl From<&[u8]> for BigInt {
    fn from(bytes: &[u8]) -> Self {
        let mut chunks = [0; N];
        for (i, slice) in bytes.chunks(8).enumerate() {
            chunks[i] = u64::from_le_bytes(slice.try_into().unwrap());
        }
        return Self { chunks };
    }
}

impl fmt::Display for BigInt {
    fn fmt (&self,  f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = String::new();
        let mut start = false;

        for chunk in self.chunks.iter().rev() {
            if !start && *chunk == 0 { continue; }

            if !start {
                start = true;
                output.push_str(format!("{:b}", chunk).as_str());
            } else {
                output.push_str(format!("{:064b}", chunk).as_str());
            }
        }

        if !start { output.push('0'); }
        return write!(f, "{}", output);
    }
}

fn big_add(own: BigInt, other: BigInt) -> BigInt {
    let mut sum;
    let mut carry = 0;
    let mut sum_overflow;
    let mut carry_overflow;
    let mut result = BigInt::zero();

    let own_iter = own.chunks.iter();
    let other_iter = other.chunks.iter();
    
    // pen and paper sum algorithm
    for (i, (own_chunk, other_chunk)) in own_iter.zip(other_iter).enumerate() {
        (sum, sum_overflow) = own_chunk.overflowing_add(*other_chunk);
        (sum, carry_overflow) = sum.overflowing_add(carry);
        result.chunks[i] = sum;
        carry = sum_overflow as u64 + carry_overflow as u64;
    }

    if carry !=0 { panic!("Overflow while adding"); }
    
    return result
}

impl Add  for BigInt {
    type Output = Self;
    fn add (self, other: Self) -> Self {
        return big_add(self, other);
    }
}

impl AddAssign for BigInt {
    fn add_assign(&mut self, other: Self) {
        *self = big_add(*self, other);
    }
}

fn big_sub(own: BigInt, other: BigInt) -> BigInt {
    let mut difference;
    let mut borrow = 0;
    let mut diff_overflow;
    let mut borrow_overflow;
    let mut result = BigInt::zero();

    let own_iter = own.chunks.iter();
    let other_iter = other.chunks.iter();

    for (i, (own_chunk, other_chunk)) in own_iter.zip(other_iter).enumerate() {
        (difference, diff_overflow) = own_chunk.overflowing_sub(*other_chunk);
        (difference, borrow_overflow) = difference.overflowing_sub(borrow);
        result.chunks[i] = difference;
        borrow = diff_overflow as u64 + borrow_overflow as u64;
    }

    if borrow != 0 { panic!("Overflow while subtracting"); }

    return result;
}

impl Sub for BigInt {
    type Output = Self;
    fn sub (self, other: Self) -> Self {
        return big_sub(self, other);
    }
}

impl SubAssign for BigInt {
    fn sub_assign(&mut self, other: Self) {
        *self = big_sub(*self, other);
    }
}

impl BigInt {
    pub fn increase(mut self) -> BigInt {
        if self.chunks[0] < u64::MAX {
            self.chunks[0] += 1;
        } else {
            self += BigInt::from(1);
        }
        return self;
    }

    // faster way to get the next odd number.
    pub fn increase_by_two(mut self) -> BigInt {
        if self.chunks[0] < u64::MAX - 1 {
            self.chunks[0] += 2;
        } else {
            self += BigInt::from(2);
        }
        return self;
    }

    pub fn decrease(mut self) -> BigInt {
        if self.chunks[0] > 0 {
            self.chunks[0] -= 1;
        } else {
            self -= BigInt::from(1);
        }
        return self;
    }
}

fn big_mul(own: BigInt, other: BigInt) -> BigInt {
    let mut result = BigInt::zero();
    let mut intermediate: u128;
    let mut carry: u128;

    let own_size = own.size();
    let other_size = other.size();
    if own_size + other_size + 1 >= N {
        panic!("Overflow while multiplying");
    }

    for (other_chunk_index, other_chunk) in other.chunks.iter().take(other_size + 1).enumerate() {
        if *other_chunk == 0 { continue; }
        carry = 0;

        for (own_chunk_index, own_chunk) in own.chunks.iter().take(own_size + 1).enumerate() {
            if *own_chunk == 0 && carry == 0 { continue; }

            intermediate = ((*own_chunk as u128) * (*other_chunk as u128)) + carry;
            intermediate += result.chunks[other_chunk_index + own_chunk_index] as u128;
            result.chunks[own_chunk_index + other_chunk_index] = intermediate as u64;
            carry = intermediate >> 64;
        }
        result.chunks[own_size + other_chunk_index + 1] += carry as u64;
    }

    return result;
}

impl Mul for BigInt {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        return big_mul(self, other);
    }
}

impl MulAssign for BigInt {
    fn mul_assign(&mut self, other:Self) {
        *self = big_mul(*self, other);
    }
}

fn big_shift_left(own: BigInt, by: usize) -> BigInt {
    let mut result = BigInt::zero();
    let mut overflow = 0;
    let mut shifted: u128;

    for (chunk_index, chunk) in own.chunks.iter().enumerate() {
        shifted = ((*chunk as u128) << by) + overflow;
        result.chunks[chunk_index] = shifted as u64;
        overflow = shifted >> 64;
    }

    return result;
}

impl Shl<usize> for BigInt {
    type Output = Self;
    fn shl(self, by: usize) -> Self {
        return big_shift_left(self, by);
    }
}

impl ShlAssign<usize> for BigInt {
    fn shl_assign(&mut self, by: usize) {
        *self = big_shift_left(*self, by);
    }
}

fn big_shift_right(own: BigInt, by: usize) -> BigInt {
    let mut result = BigInt::zero();
    let mut overflow = 0;
    let mut shifted: u128;

    for (chunk_index, chunk) in own.chunks.iter().enumerate().rev() {
        shifted = ((*chunk as u128) << (64 - by)) + (overflow << 64);
        overflow = (shifted as u64) as u128;
        result.chunks[chunk_index] = (shifted >> 64) as u64;
    }

    return result;
}

impl Shr<usize> for BigInt {
    type Output = Self;
    fn shr(self, by: usize) -> Self {
        return big_shift_right(self, by);
    }
}

impl ShrAssign<usize> for BigInt {
    fn shr_assign(&mut self, by: usize) {
        *self = big_shift_right(*self, by);
    }
}

impl PartialEq for BigInt {
    fn eq(&self, other: &Self) -> bool {
        self.chunks == other.chunks
    }
}

impl PartialOrd for BigInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        for (own_chunk, other_chunk) in self.chunks.iter().zip(other.chunks.iter()).rev() {
            if *own_chunk != *other_chunk {
                return own_chunk.partial_cmp(other_chunk);
            }
        }
        Some(Ordering::Equal)
    }
}

impl BigInt {
    fn size(&self) -> usize {
        let mut n = N - 1;
        for chunk in self.chunks.iter().rev(){
            if *chunk != 0 { break; }
            n -= 1;
        }
        return n;
    }
}

fn big_div(mut dividend: BigInt, mut divisor: BigInt) -> (BigInt, BigInt){
    if divisor.is_zero() { panic!("Division by zero"); }
    if dividend < divisor { return (BigInt::zero(), dividend); }

    let mut quotient = BigInt::zero();
    let mut lambda = 0;

    let t = divisor.size();

    if divisor.chunks[t] < u64::MAX / 2 {
        while (divisor.chunks[t] << lambda) < u64::MAX / 2 {
            lambda += 1;
        }
        divisor <<= lambda;
        dividend <<= lambda; 
    }

    let n = dividend.size();

    // if divisor has only one digit do long division  
    if t == 0 {
        let divisor_digit = divisor.chunks[0] as u128;
        let mut remainder = 0;
        let mut current;
        for (chunk_index, chunk) in dividend.chunks.iter().enumerate().rev().skip(N-n-1) {
            current = (remainder << 64) + *chunk as u128;
            quotient.chunks[chunk_index] = (current / divisor_digit) as u64;
            remainder = current % divisor_digit;
        }
        return (quotient, BigInt::from(remainder >> lambda));
    }

    // align and subtract divisor from dividend until dividend is >= aligned
    let mut aligned = divisor.clone();
    for _ in 0..(n - t) {
        aligned <<= 64;
    }

    while dividend >= aligned {
        quotient.chunks[n - t] += 1;
        dividend -= aligned;
    }

    let one = BigInt::from(1);
    let mut x_3digit;
    let mut y_2digit;
    let mut q_u128;
    let mut q_digit;


    for i in ((t+1)..=n).rev() {
        q_digit = BigInt::zero();

        if dividend.chunks[i] == divisor.chunks[t] {
            q_digit.chunks[0] = u64::MAX - 1;
        } else {
            q_u128 = (dividend.chunks[i] as u128) << 64;
            q_u128 += dividend.chunks[i-1] as u128;
            q_digit = BigInt::from(q_u128 / divisor.chunks[t] as u128);
        }

        x_3digit = BigInt::zero();
        x_3digit.chunks[2] = dividend.chunks[i];
        x_3digit.chunks[1] = dividend.chunks[i-1];
        x_3digit.chunks[0] = dividend.chunks[i-2];

        y_2digit = BigInt::zero();
        y_2digit.chunks[1] = divisor.chunks[t];
        y_2digit.chunks[0] = divisor.chunks[t-1];

        while q_digit * y_2digit > x_3digit {
            q_digit -= one;
        }

        quotient.chunks[i-t-1] = q_digit.chunks[0];

        let mut y_shifted = divisor.clone();
        for _ in 0..(i-t-1) {
            y_shifted <<= 64;
        }

        if dividend >= q_digit * y_shifted {
            dividend -= q_digit * y_shifted;
        } else {
            dividend += y_shifted;
            dividend -= q_digit * y_shifted;
            quotient.chunks[i-t-1] -= 1;
        }
    }

    dividend >>= lambda;

    return (quotient, dividend);
}

impl Div for BigInt {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        big_div(self, other).0
    }
}

impl DivAssign for BigInt {
    fn div_assign(&mut self, other: Self){
        *self = big_div(*self, other).0;
    }
}

impl Rem for BigInt {
    type Output = Self;
    fn rem(self, other: Self) -> Self {
        big_div(self, other).1
    }
}

impl RemAssign for BigInt {
    fn rem_assign(&mut self, other: Self) {
        *self = big_div(*self, other).1;
    }
}

pub fn gcd(mut a: BigInt, mut b: BigInt) -> BigInt {
    while !b.is_zero() {
        let r = a % b;
        a = b;
        b = r;
    }
    return a;
}