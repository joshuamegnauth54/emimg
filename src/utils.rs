// SPDX-License-Identifier: GPL-3.0-or-later

use core::{
    fmt::{self, Write},
    hint::cold_path,
};

pub struct BufferFmtWriter<'buf> {
    buf: &'buf mut [u8],
    pos: usize,
}

impl<'buf> BufferFmtWriter<'buf> {
    pub const fn new(buf: &'buf mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub const fn as_str(&self) -> &str {
        unsafe { str::from_utf8_unchecked(&self.buf[..pos]) }
    }

    pub const fn clear(&mut self) {
        self.pos = 0;
    }
}

impl Write for BufferFmtWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        debug_assert!(
            self.pos <= self.buf.len(),
            "Buffer position should never exceed buffer length"
        );

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
