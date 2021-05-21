/// Determine whether the bit at the specified `index`, counted from the least
/// significant bit, is set in the specified `value`.
pub const fn bit_is_set(value: u32, index: u8) -> bool {
    value & (1 << index) != 0
}

/// Select the specified number of bits (`size`) beginning at the specified
/// `low_bit` index in the specified `value`.  The resulting value will feature
/// the low bit shifted into index `0`.
pub const fn select_bits(value: u32, low_bit: u8, size: u8) -> u32 {
    (value >> low_bit) & ((1 << size) - 1)
}

/// Extend the value of the bit in the specified `sign_bit` of the specified
/// `value` through all bits above the sign bit.
pub const fn sign_extend(value: u32, sign_bit: u8) -> i32 {
    let shift = 31 - sign_bit;
    ((value as i32) << shift) >> shift
}
