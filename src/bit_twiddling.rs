use num_traits::{AsPrimitive, PrimInt, Signed, Unsigned};
use std::mem;

/// A simple trait to encode a signed and unsigned integer type of the same
/// width, implemented manually for each type.
pub trait SwapSignedness: PrimInt {
    type Signed: PrimInt + Signed;
    type Unsigned: PrimInt + Unsigned;
}

/// Define a pair of `(Signed, Unsigned)` integer types.
macro_rules! define_swap_signedness {
    ($signed:ty, $unsigned:ty) => {
        impl SwapSignedness for $signed {
            type Signed = $signed;
            type Unsigned = $unsigned;
        }
        impl SwapSignedness for $unsigned {
            type Signed = $signed;
            type Unsigned = $unsigned;
        }
    };
}

define_swap_signedness!(i8, u8);
define_swap_signedness!(i16, u16);
define_swap_signedness!(i32, u32);
define_swap_signedness!(i64, u64);
define_swap_signedness!(i128, u128);
define_swap_signedness!(isize, usize);

/// A wrapper trait for various bit-twiddling operations on unsigned integers.
pub trait BitTwiddling<TIndex: AsPrimitive<usize>>: SwapSignedness + AsPrimitive<Self::Signed> {
    /// Generate an integral value containing the bit at the specified `index`,
    /// `set` to `0` or `1` according to the specified value.
    fn bit(index: TIndex, set: bool) -> Self;

    /// Determine whether the bit at the specified `index`, counted from the
    /// least significant bit, is set in this integral value.
    fn bit_is_set(self, index: TIndex) -> bool;

    /// Select the specified number of bits (`size`) beginning at the specified
    /// `low_bit` index into this value.  The resulting value will feature the
    /// low bit shifted into index `0`.
    ///
    /// # Future Considerations
    /// At some point, it would be extremely nice to be able to specify the
    /// output type with a default value of `Self`; however, due to the
    /// prohibition of the feature `invalid_type_param_default` and lack of a
    /// working replacement, some `as` casting of the result of this function is
    /// sometimes required in current versions of Rust.
    fn select_bits(self, low_bit: TIndex, size: TIndex) -> Self;

    /// Extend the value of the bit in the specified `sign_bit` of this value
    /// through all bits above the sign bit.
    fn sign_extend(self, sign_bit: TIndex) -> Self::Signed;
}

impl<T, TIndex> BitTwiddling<TIndex> for T
where
    T: SwapSignedness + AsPrimitive<T::Signed>,
    TIndex: AsPrimitive<usize>,
{
    fn bit(index: TIndex, set: bool) -> T {
        (if set { T::one() } else { T::zero() }) << index.as_()
    }

    fn bit_is_set(self, index: TIndex) -> bool {
        self & (T::one() << index.as_()) != T::zero()
    }

    fn select_bits(self, low_bit: TIndex, size: TIndex) -> T {
        (self >> low_bit.as_()) & ((T::one() << size.as_()) - T::one())
    }

    fn sign_extend(self, sign_bit: TIndex) -> T::Signed {
        let shift = mem::size_of::<T>() * 8 - sign_bit.as_() - 1;
        (self.as_() << shift) >> shift
    }
}
