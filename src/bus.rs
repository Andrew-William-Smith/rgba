use crate::cpu::Address;

/// An error caused by an invalid memory bus operation.
pub enum BusError {
    /// A program attempted to read from or write to an unhandled address.
    InvalidAddress,
}

/// Interface required for a readable device on the system bus.  Allows reading
/// values in all of the formats supported by the CPU.
pub trait Readable {
    /// Attempt to read a byte of data from the specified memory address.
    ///
    /// # Errors
    /// - `BusError::InvalidAddress` if the requested address is not handled by
    ///   this device.
    fn read(&self, address: Address) -> Result<u8, BusError>;
}

/// The system bus, which serves as a communication medium between the various
/// computational units in the Game Boy Advance and the system's memory in its
/// various forms.  Control of the bus is transferred to each component as it is
/// needed, mimicking a fairly realistic synchronous bus protocol.
pub struct Bus {
    /// The system's on-board Work RAM (WRAM), which is divided into two address
    /// ranges: `0x02000000`&ndash;`0203FFFF` (2 additional cycles per access)
    /// and `0x03000000`&ndash;`03007FFF`.  These ranges are merged into one
    /// contiguous range on the bus.
    pub ram: [u8; 294_912],
}

impl Readable for Bus {
    fn read(&self, address: Address) -> Result<u8, BusError> {
        let address_idx = address as usize;

        match address {
            0x0200_0000..=0x0203_FFFF => Ok(self.ram[address_idx - 0x0200_0000]),
            0x0300_0000..=0x0300_7FFF => Ok(self.ram[address_idx - 0x02FC_0000]),
            _ => Err(BusError::InvalidAddress),
        }
    }
}

impl Bus {
    /// Attempt to read a half word (16 bits, 2 bytes) of memory with a low byte
    /// at the specified address as a little-endian value.
    ///
    /// # Errors
    /// - `BusError::InvalidAddress` if either byte of the half word is outside
    ///   the range handled by any device on the bus.
    pub fn read_half_word(&self, address: Address) -> Result<u16, BusError> {
        let low_byte = self.read(address)? as u16;
        let high_byte = self.read(address + 1)? as u16;
        Ok((high_byte << 8) | low_byte)
    }

    /// Attempt to read a full word (32 bits, 4 bytes) of memory with a least
    /// significant byte at the specified address as a little-endian value.
    ///
    /// # Errors
    /// - `BusError::InvalidAddress` if any byte of the word is outside the
    ///   range handled by any device on the bus.
    pub fn read_word(&self, address: Address) -> Result<u32, BusError> {
        let byte0 = self.read(address)? as u32;
        let byte1 = self.read(address + 1)? as u32;
        let byte2 = self.read(address + 2)? as u32;
        let byte3 = self.read(address + 3)? as u32;
        Ok((byte3 << 24) | (byte2 << 16) | (byte1 << 8) | byte0)
    }
}
