use core::cmp::min;
use core::fmt;

use crate::error::RnsError;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct StaticBuffer<const N: usize> {
    buffer: [u8; N],
    len: usize,
}

impl<const N: usize> StaticBuffer<N> {
    pub const fn new() -> Self {
        Self {
            buffer: [0u8; N],
            len: 0,
        }
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        let mut buffer = Self::new();

        buffer.safe_write(data);

        buffer
    }

    pub fn reset(&mut self) {
        self.len = 0;
    }

    pub fn resize(&mut self, len: usize) {
        self.len = min(len, self.buffer.len());
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the buffer contains no data.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn chain_write(&mut self, data: &[u8]) -> Result<&mut Self, RnsError> {
        self.write(data)?;
        Ok(self)
    }

    pub fn finalize(self) -> Self {
        self
    }

    pub fn safe_write(&mut self, data: &[u8]) -> usize {
        let data_size = data.len();

        let max_size = core::cmp::min(data_size, N - self.len);

        self.write(&data[..max_size]).unwrap_or(0)
    }

    pub fn chain_safe_write(&mut self, data: &[u8]) -> &mut Self {
        self.safe_write(data);
        self
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize, RnsError> {
        let data_size = data.len();

        // Nothing to write
        if data_size == 0 {
            return Ok(0);
        }

        if (self.len + data_size) > N {
            return Err(RnsError::OutOfMemory);
        }

        self.buffer[self.len..(self.len + data_size)].copy_from_slice(data);
        self.len += data_size;

        Ok(data_size)
    }

    pub fn rotate_left(&mut self, mid: usize) -> Result<usize, RnsError> {
        if mid > self.len {
            return Err(RnsError::InvalidArgument);
        }

        self.len -= mid;

        self.buffer.rotate_left(mid);

        Ok(self.len)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.len]
    }

    /// Acquire a mutable buffer of exactly `len` bytes, setting the
    /// logical length. Returns `BufferOverflow` if `len` exceeds capacity.
    pub fn accuire_buf(&mut self, len: usize) -> Result<&mut [u8], RnsError> {
        if len > N {
            return Err(RnsError::BufferOverflow);
        }
        self.len = len;
        Ok(&mut self.buffer[..self.len])
    }

    pub fn accuire_buf_max(&mut self) -> &mut [u8] {
        self.len = self.buffer.len();
        &mut self.buffer[..self.len]
    }
}

impl<const N: usize> Default for StaticBuffer<N> {
    fn default() -> Self {
        Self {
            buffer: [0u8; N],
            len: 0,
        }
    }
}

pub struct OutputBuffer<'a> {
    buffer: &'a mut [u8],
    offset: usize,
}

impl<'a> OutputBuffer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { offset: 0, buffer }
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize, RnsError> {
        let data_size = data.len();

        // Nothing to write
        if data_size == 0 {
            return Ok(0);
        }

        if (self.offset + data_size) > self.buffer.len() {
            return Err(RnsError::OutOfMemory);
        }

        self.buffer[self.offset..(self.offset + data_size)].copy_from_slice(data);
        self.offset += data_size;

        Ok(data_size)
    }

    pub fn write_byte(&mut self, byte: u8) -> Result<usize, RnsError> {
        self.write(&[byte])
    }

    pub fn reset(&mut self) {
        self.offset = 0;
    }

    pub fn is_full(&self) -> bool {
        self.offset == self.buffer.len()
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.offset]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.offset]
    }
}

impl<'a> fmt::Display for OutputBuffer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ 0x")?;

        for i in 0..self.offset {
            write!(f, "{:0>2x}", self.buffer[i])?;
        }

        write!(f, " ]",)
    }
}

impl<const N: usize> fmt::Display for StaticBuffer<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ 0x")?;

        for i in 0..self.len {
            write!(f, "{:0>2x}", self.buffer[i])?;
        }

        write!(f, " ]",)
    }
}

pub struct InputBuffer<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> InputBuffer<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { offset: 0, buffer }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, RnsError> {
        let size = buf.len();
        if (self.offset + size) > self.buffer.len() {
            return Err(RnsError::OutOfMemory);
        }

        buf.copy_from_slice(&self.buffer[self.offset..(self.offset + size)]);
        self.offset += size;

        Ok(size)
    }

    pub fn read_size(&mut self, buf: &mut [u8], size: usize) -> Result<usize, RnsError> {
        if (self.offset + size) > self.buffer.len() {
            return Err(RnsError::OutOfMemory);
        }

        if buf.len() < size {
            return Err(RnsError::OutOfMemory);
        }

        buf[..size].copy_from_slice(&self.buffer[self.offset..(self.offset + size)]);
        self.offset += size;

        Ok(size)
    }

    pub fn read_byte(&mut self) -> Result<u8, RnsError> {
        let mut buf = [0u8; 1];
        self.read(&mut buf)?;

        Ok(buf[0])
    }

    pub fn read_slice(&mut self, size: usize) -> Result<&[u8], RnsError> {
        if (self.offset + size) > self.buffer.len() {
            return Err(RnsError::OutOfMemory);
        }

        let slice = &self.buffer[self.offset..self.offset + size];

        self.offset += size;

        Ok(slice)
    }

    pub fn bytes_left(&self) -> usize {
        self.buffer.len() - self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== StaticBuffer Tests ====================

    mod static_buffer {
        use super::*;

        // Basic operations
        #[test]
        fn test_new_creates_empty_buffer() {
            let buffer = StaticBuffer::<256>::new();
            assert_eq!(buffer.len(), 0);
            assert!(buffer.is_empty());
        }

        #[test]
        fn test_new_from_slice_copies_data() {
            let data = [1u8, 2, 3, 4, 5];
            let buffer = StaticBuffer::<256>::new_from_slice(&data);
            assert_eq!(buffer.len(), 5);
            assert_eq!(buffer.as_slice(), &data);
        }

        #[test]
        fn test_new_from_slice_truncates_overflow() {
            let data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            let buffer = StaticBuffer::<5>::new_from_slice(&data);
            assert_eq!(buffer.len(), 5);
            assert_eq!(buffer.as_slice(), &[1, 2, 3, 4, 5]);
        }

        #[test]
        fn test_reset_clears_buffer() {
            let mut buffer = StaticBuffer::<256>::new_from_slice(&[1, 2, 3]);
            assert_eq!(buffer.len(), 3);
            buffer.reset();
            assert_eq!(buffer.len(), 0);
            assert!(buffer.is_empty());
        }

        #[test]
        fn test_default_creates_empty_buffer() {
            let buffer = StaticBuffer::<256>::default();
            assert_eq!(buffer.len(), 0);
            assert!(buffer.is_empty());
        }

        // Write operations
        #[test]
        fn test_write_single_byte() {
            let mut buffer = StaticBuffer::<256>::new();
            let result = buffer.write(&[42]);
            assert_eq!(result, Ok(1));
            assert_eq!(buffer.len(), 1);
            assert_eq!(buffer.as_slice(), &[42]);
        }

        #[test]
        fn test_write_multiple_bytes() {
            let mut buffer = StaticBuffer::<256>::new();
            buffer.write(&[1, 2, 3]).unwrap();
            buffer.write(&[4, 5]).unwrap();
            assert_eq!(buffer.len(), 5);
            assert_eq!(buffer.as_slice(), &[1, 2, 3, 4, 5]);
        }

        #[test]
        fn test_write_exact_capacity() {
            let mut buffer = StaticBuffer::<5>::new();
            let result = buffer.write(&[1, 2, 3, 4, 5]);
            assert_eq!(result, Ok(5));
            assert_eq!(buffer.len(), 5);
        }

        #[test]
        fn test_write_overflow_returns_error() {
            let mut buffer = StaticBuffer::<5>::new();
            buffer.write(&[1, 2, 3]).unwrap();
            let result = buffer.write(&[4, 5, 6]);
            assert_eq!(result, Err(RnsError::OutOfMemory));
            assert_eq!(buffer.len(), 3); // Unchanged
        }

        #[test]
        fn test_write_empty_data() {
            let mut buffer = StaticBuffer::<256>::new();
            let result = buffer.write(&[]);
            assert_eq!(result, Ok(0));
            assert_eq!(buffer.len(), 0);
        }

        #[test]
        fn test_chain_write_returns_self() {
            let mut buffer = StaticBuffer::<256>::new();
            buffer
                .chain_write(&[1, 2])
                .unwrap()
                .chain_write(&[3, 4])
                .unwrap();
            assert_eq!(buffer.as_slice(), &[1, 2, 3, 4]);
        }

        // Safe write operations
        #[test]
        fn test_safe_write_returns_bytes_written() {
            let mut buffer = StaticBuffer::<256>::new();
            let written = buffer.safe_write(&[1, 2, 3]);
            assert_eq!(written, 3);
        }

        #[test]
        fn test_safe_write_truncates_overflow() {
            let mut buffer = StaticBuffer::<5>::new();
            buffer.safe_write(&[1, 2, 3]);
            let written = buffer.safe_write(&[4, 5, 6, 7, 8]);
            assert_eq!(written, 2); // Only 2 bytes fit
            assert_eq!(buffer.as_slice(), &[1, 2, 3, 4, 5]);
        }

        #[test]
        fn test_safe_write_when_full() {
            let mut buffer = StaticBuffer::<3>::new();
            buffer.safe_write(&[1, 2, 3]);
            let written = buffer.safe_write(&[4]);
            assert_eq!(written, 0);
        }

        #[test]
        fn test_chain_safe_write_returns_self() {
            let mut buffer = StaticBuffer::<256>::new();
            buffer.chain_safe_write(&[1, 2]).chain_safe_write(&[3, 4]);
            assert_eq!(buffer.as_slice(), &[1, 2, 3, 4]);
        }

        // Resize operations
        #[test]
        fn test_resize_increases_length() {
            let mut buffer = StaticBuffer::<256>::new();
            buffer.resize(100);
            assert_eq!(buffer.len(), 100);
        }

        #[test]
        fn test_resize_decreases_length() {
            let mut buffer = StaticBuffer::<256>::new_from_slice(&[1, 2, 3, 4, 5]);
            buffer.resize(2);
            assert_eq!(buffer.len(), 2);
        }

        #[test]
        fn test_resize_clamps_to_capacity() {
            let mut buffer = StaticBuffer::<10>::new();
            buffer.resize(100);
            assert_eq!(buffer.len(), 10);
        }

        #[test]
        fn test_resize_to_zero() {
            let mut buffer = StaticBuffer::<256>::new_from_slice(&[1, 2, 3]);
            buffer.resize(0);
            assert_eq!(buffer.len(), 0);
        }

        // Rotate operations
        #[test]
        fn test_rotate_left_basic() {
            let mut buffer = StaticBuffer::<256>::new_from_slice(&[1, 2, 3, 4, 5]);
            let result = buffer.rotate_left(2);
            assert_eq!(result, Ok(3));
            assert_eq!(buffer.len(), 3);
            assert_eq!(buffer.as_slice(), &[3, 4, 5]);
        }

        #[test]
        fn test_rotate_left_full_length() {
            let mut buffer = StaticBuffer::<256>::new_from_slice(&[1, 2, 3]);
            let result = buffer.rotate_left(3);
            assert_eq!(result, Ok(0));
            assert!(buffer.is_empty());
        }

        #[test]
        fn test_rotate_left_zero() {
            let mut buffer = StaticBuffer::<256>::new_from_slice(&[1, 2, 3]);
            let result = buffer.rotate_left(0);
            assert_eq!(result, Ok(3));
            assert_eq!(buffer.as_slice(), &[1, 2, 3]);
        }

        #[test]
        fn test_rotate_left_beyond_length_errors() {
            let mut buffer = StaticBuffer::<256>::new_from_slice(&[1, 2, 3]);
            let result = buffer.rotate_left(5);
            assert_eq!(result, Err(RnsError::InvalidArgument));
        }

        // Slice access
        #[test]
        fn test_as_slice_returns_valid_data() {
            let buffer = StaticBuffer::<256>::new_from_slice(&[1, 2, 3]);
            assert_eq!(buffer.as_slice(), &[1, 2, 3]);
        }

        #[test]
        fn test_as_mut_slice_allows_modification() {
            let mut buffer = StaticBuffer::<256>::new_from_slice(&[1, 2, 3]);
            buffer.as_mut_slice()[0] = 99;
            assert_eq!(buffer.as_slice(), &[99, 2, 3]);
        }

        #[test]
        fn test_accuire_buf_sets_length() {
            let mut buffer = StaticBuffer::<256>::new();
            let slice = buffer.accuire_buf(10).unwrap();
            assert_eq!(slice.len(), 10);
            assert_eq!(buffer.len(), 10);
        }

        #[test]
        fn test_accuire_buf_overflow_returns_error() {
            let mut buffer = StaticBuffer::<10>::new();
            assert_eq!(buffer.accuire_buf(11), Err(RnsError::BufferOverflow));
            assert_eq!(buffer.len(), 0); // Length unchanged on error
        }

        #[test]
        fn test_accuire_buf_exact_capacity_succeeds() {
            let mut buffer = StaticBuffer::<10>::new();
            let slice = buffer.accuire_buf(10).unwrap();
            assert_eq!(slice.len(), 10);
        }

        #[test]
        fn test_accuire_buf_max_fills_buffer() {
            let mut buffer = StaticBuffer::<64>::new();
            let slice = buffer.accuire_buf_max();
            assert_eq!(slice.len(), 64);
            assert_eq!(buffer.len(), 64);
        }

        // Display
        #[test]
        fn test_display_empty_buffer() {
            let buffer = StaticBuffer::<256>::new();
            let display = format!("{}", buffer);
            assert_eq!(display, "[ 0x ]");
        }

        #[test]
        fn test_display_with_data() {
            let buffer = StaticBuffer::<256>::new_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            let display = format!("{}", buffer);
            assert_eq!(display, "[ 0xdeadbeef ]");
        }

        #[test]
        fn test_finalize_returns_self() {
            let buffer = StaticBuffer::<256>::new_from_slice(&[1, 2, 3]);
            let finalized = buffer.finalize();
            assert_eq!(finalized.as_slice(), &[1, 2, 3]);
        }
    }

    // ==================== OutputBuffer Tests ====================

    mod output_buffer {
        use super::*;

        #[test]
        fn test_new_starts_at_zero() {
            let mut backing = [0u8; 256];
            let buffer = OutputBuffer::new(&mut backing);
            assert_eq!(buffer.offset(), 0);
            assert!(!buffer.is_full());
        }

        #[test]
        fn test_write_single_byte() {
            let mut backing = [0u8; 256];
            let mut buffer = OutputBuffer::new(&mut backing);
            let result = buffer.write(&[42]);
            assert_eq!(result, Ok(1));
            assert_eq!(buffer.offset(), 1);
            assert_eq!(buffer.as_slice(), &[42]);
        }

        #[test]
        fn test_write_multiple_sequential() {
            let mut backing = [0u8; 256];
            let mut buffer = OutputBuffer::new(&mut backing);
            buffer.write(&[1, 2, 3]).unwrap();
            buffer.write(&[4, 5]).unwrap();
            assert_eq!(buffer.offset(), 5);
            assert_eq!(buffer.as_slice(), &[1, 2, 3, 4, 5]);
        }

        #[test]
        fn test_write_exact_capacity() {
            let mut backing = [0u8; 5];
            let mut buffer = OutputBuffer::new(&mut backing);
            buffer.write(&[1, 2, 3, 4, 5]).unwrap();
            assert!(buffer.is_full());
        }

        #[test]
        fn test_write_overflow_returns_error() {
            let mut backing = [0u8; 5];
            let mut buffer = OutputBuffer::new(&mut backing);
            buffer.write(&[1, 2, 3]).unwrap();
            let result = buffer.write(&[4, 5, 6]);
            assert_eq!(result, Err(RnsError::OutOfMemory));
        }

        #[test]
        fn test_write_byte_method() {
            let mut backing = [0u8; 256];
            let mut buffer = OutputBuffer::new(&mut backing);
            buffer.write_byte(42).unwrap();
            buffer.write_byte(43).unwrap();
            assert_eq!(buffer.as_slice(), &[42, 43]);
        }

        #[test]
        fn test_reset_clears_offset() {
            let mut backing = [0u8; 256];
            let mut buffer = OutputBuffer::new(&mut backing);
            buffer.write(&[1, 2, 3]).unwrap();
            buffer.reset();
            assert_eq!(buffer.offset(), 0);
        }

        #[test]
        fn test_write_after_reset() {
            let mut backing = [0u8; 256];
            let mut buffer = OutputBuffer::new(&mut backing);
            buffer.write(&[1, 2, 3]).unwrap();
            buffer.reset();
            buffer.write(&[4, 5]).unwrap();
            assert_eq!(buffer.as_slice(), &[4, 5]);
        }

        #[test]
        fn test_is_full_accurate() {
            let mut backing = [0u8; 3];
            let mut buffer = OutputBuffer::new(&mut backing);
            assert!(!buffer.is_full());
            buffer.write(&[1, 2]).unwrap();
            assert!(!buffer.is_full());
            buffer.write(&[3]).unwrap();
            assert!(buffer.is_full());
        }

        #[test]
        fn test_as_mut_slice_allows_modification() {
            let mut backing = [0u8; 256];
            let mut buffer = OutputBuffer::new(&mut backing);
            buffer.write(&[1, 2, 3]).unwrap();
            buffer.as_mut_slice()[0] = 99;
            assert_eq!(buffer.as_slice(), &[99, 2, 3]);
        }

        #[test]
        fn test_display_format() {
            let mut backing = [0u8; 256];
            let mut buffer = OutputBuffer::new(&mut backing);
            buffer.write(&[0xca, 0xfe]).unwrap();
            let display = format!("{}", buffer);
            assert_eq!(display, "[ 0xcafe ]");
        }

        #[test]
        fn test_write_empty_data() {
            let mut backing = [0u8; 256];
            let mut buffer = OutputBuffer::new(&mut backing);
            let result = buffer.write(&[]);
            assert_eq!(result, Ok(0));
            assert_eq!(buffer.offset(), 0);
        }
    }

    // ==================== InputBuffer Tests ====================

    mod input_buffer {
        use super::*;

        #[test]
        fn test_new_starts_at_zero() {
            let data = [1u8, 2, 3, 4, 5];
            let buffer = InputBuffer::new(&data);
            assert_eq!(buffer.bytes_left(), 5);
        }

        #[test]
        fn test_read_single_byte() {
            let data = [42u8, 43, 44];
            let mut buffer = InputBuffer::new(&data);
            let byte = buffer.read_byte().unwrap();
            assert_eq!(byte, 42);
            assert_eq!(buffer.bytes_left(), 2);
        }

        #[test]
        fn test_read_multiple_sequential() {
            let data = [1u8, 2, 3, 4, 5];
            let mut buffer = InputBuffer::new(&data);
            let mut out1 = [0u8; 2];
            let mut out2 = [0u8; 3];
            buffer.read(&mut out1).unwrap();
            buffer.read(&mut out2).unwrap();
            assert_eq!(out1, [1, 2]);
            assert_eq!(out2, [3, 4, 5]);
            assert_eq!(buffer.bytes_left(), 0);
        }

        #[test]
        fn test_read_exact_amount() {
            let data = [1u8, 2, 3, 4, 5];
            let mut buffer = InputBuffer::new(&data);
            let mut out = [0u8; 5];
            buffer.read(&mut out).unwrap();
            assert_eq!(out, [1, 2, 3, 4, 5]);
            assert_eq!(buffer.bytes_left(), 0);
        }

        #[test]
        fn test_read_overflow_returns_error() {
            let data = [1u8, 2, 3];
            let mut buffer = InputBuffer::new(&data);
            let mut out = [0u8; 5];
            let result = buffer.read(&mut out);
            assert_eq!(result, Err(RnsError::OutOfMemory));
        }

        #[test]
        fn test_read_slice_method() {
            let data = [1u8, 2, 3, 4, 5];
            let mut buffer = InputBuffer::new(&data);
            let slice = buffer.read_slice(3).unwrap();
            assert_eq!(slice, &[1, 2, 3]);
            assert_eq!(buffer.bytes_left(), 2);
        }

        #[test]
        fn test_read_slice_advances_offset() {
            let data = [1u8, 2, 3, 4, 5];
            let mut buffer = InputBuffer::new(&data);
            buffer.read_slice(2).unwrap();
            let slice = buffer.read_slice(2).unwrap();
            assert_eq!(slice, &[3, 4]);
        }

        #[test]
        fn test_read_size_with_smaller_request() {
            let data = [1u8, 2, 3, 4, 5];
            let mut buffer = InputBuffer::new(&data);
            let mut out = [0u8; 10];
            let result = buffer.read_size(&mut out, 3);
            assert_eq!(result, Ok(3));
            assert_eq!(&out[..3], &[1, 2, 3]);
        }

        #[test]
        fn test_read_size_buffer_too_small() {
            let data = [1u8, 2, 3, 4, 5];
            let mut buffer = InputBuffer::new(&data);
            let mut out = [0u8; 2];
            let result = buffer.read_size(&mut out, 5);
            assert_eq!(result, Err(RnsError::OutOfMemory));
        }

        #[test]
        fn test_read_size_not_enough_data() {
            let data = [1u8, 2, 3];
            let mut buffer = InputBuffer::new(&data);
            let mut out = [0u8; 10];
            let result = buffer.read_size(&mut out, 5);
            assert_eq!(result, Err(RnsError::OutOfMemory));
        }

        #[test]
        fn test_bytes_left_decreases() {
            let data = [1u8, 2, 3, 4, 5];
            let mut buffer = InputBuffer::new(&data);
            assert_eq!(buffer.bytes_left(), 5);
            buffer.read_byte().unwrap();
            assert_eq!(buffer.bytes_left(), 4);
            buffer.read_slice(2).unwrap();
            assert_eq!(buffer.bytes_left(), 2);
        }

        #[test]
        fn test_read_empty_buffer() {
            let data: [u8; 0] = [];
            let mut buffer = InputBuffer::new(&data);
            assert_eq!(buffer.bytes_left(), 0);
            let result = buffer.read_byte();
            assert_eq!(result, Err(RnsError::OutOfMemory));
        }

        #[test]
        fn test_partial_read_then_exhausted() {
            let data = [1u8, 2, 3];
            let mut buffer = InputBuffer::new(&data);
            buffer.read_byte().unwrap();
            buffer.read_byte().unwrap();
            buffer.read_byte().unwrap();
            let result = buffer.read_byte();
            assert_eq!(result, Err(RnsError::OutOfMemory));
        }
    }
}
