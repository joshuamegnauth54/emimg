// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(feature = "rust-libc")]
use libc_rust as libc;

use core::{
    ffi::CStr,
    fmt::{self, Write},
    hint::cold_path,
};

pub struct BufferFmtWriter<'buf> {
    buf: &'buf mut [u8],
    pos: usize,
}

impl<'buf> BufferFmtWriter<'buf> {
    #[inline(always)]
    pub const fn new(buf: &'buf mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[must_use]
    #[inline(always)]
    pub const fn as_bytes(&self) -> &[u8] {
        // TODO: const Index
        // SAFETY: See `as_str`
        unsafe { self.buf.split_at_unchecked(self.pos) }.0
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        // TODO: const Index
        // SAFETY:
        // * `pos` is a usize so it can't be negative and is initialized as 0
        // * `pos` is checked to be less than len() in write_str()
        let (buf, _) = unsafe { self.buf.split_at_unchecked(self.pos) };
        // SAFETY: All writes go through fmt::Write which requires valid UTF-8
        unsafe { str::from_utf8_unchecked(buf) }
    }

    #[must_use]
    pub const fn as_c_str(&mut self) -> Option<&CStr> {
        // This internal helper is highly bounded so this shouldn't happen.
        if self.pos >= self.buf.len() {
            cold_path();
            return None;
        }

        if self.buf[self.pos] != 0 {
            self.buf[self.pos] = 0;
            // Deliberately not updating self.pos here so that subsequent writes overwrite the NUL.
        }

        // TODO: const Index
        unsafe {
            Some(CStr::from_bytes_with_nul_unchecked(
                self.buf.split_at_unchecked(self.pos + 1).0,
            ))
        }
    }

    #[inline(always)]
    pub const fn clear(&mut self) {
        self.pos = 0;
    }
}

impl Write for BufferFmtWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if !unsafe { libc::memchr(s.as_ptr().cast(), 0, s.len()) }.is_null() {
            cold_path();
            return Err(fmt::Error);
        }

        let end = self.pos + s.len();
        if end > self.buf.len() {
            // BufferFmtWriter is an internal, implementation detail. It's unlikely I'd actually
            // overwrite into this buffer. It's simply to avoid allocating a string or adding an
            // extra dependency for such.
            cold_path();
            return Err(fmt::Error);
        }
        self.buf[self.pos..end].copy_from_slice(s.as_bytes());
        self.pos = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    compile_error!("WRITE TESTS DANG IT");
}
