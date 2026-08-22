// Lightweight JSON builder that writes directly into a byte buffer
pub struct JsonWriter {
    buf: Vec<u8>,
    first: bool, // trach comma for object fields
}

impl JsonWriter {
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(512), first: true }
    }

    pub fn begin_object(&mut self) {
        self.buf.push(b'{');
        self.first = true;
    }

    pub fn end_object(&mut self) {
        self.buf.push(b'}');
        self.first = false;
    }

    fn comma(&mut self) {
        if !self.first {
            self.buf.push(b',');
        }
        self.first = false;
    }

    fn write_key(&mut self, key: &str) {
        self.comma();
        self.buf.push(b'"');
        self.buf.extend_from_slice(key.as_bytes());
        self.buf.push(b'"');
        self.buf.push(b':');
    }

    pub fn key_str(&mut self, key: &str, value: &str) {
        self.write_key(key);
        self.buf.push(b'"');
        // Excape special characters
        for &b in value.as_bytes() {
            match b {
                b'"' => {
                    self.buf.push(b'\\');
                    self.buf.push(b'"');
                }
                b'\\' => {
                    self.buf.push(b'\\');
                    self.buf.push(b'\\');
                }
                b'\n' => {
                    self.buf.push(b'\\');
                    self.buf.push(b'n');
                }
                b'\r' => {
                    self.buf.push(b'\\');
                    self.buf.push(b'r');
                }
                b'\t' => {
                    self.buf.push(b'\\');
                    self.buf.push(b't');
                }
                _ if b < 0x20 => {
                    // control characters: \u00XX
                    self.buf.extend_from_slice(b"\\u00");
                    let hi = b >> 4;
                    let lo = b & 0x0F;
                    self.buf.push(if hi < 10 { b'0' + hi } else { b'a' + hi - 10 });
                    self.buf.push(if lo < 10 { b'0' + lo } else { b'a' + lo - 10 });
                }
                _ => self.buf.push(b),
            }
        }
        self.buf.push(b'"');
    }

    pub fn key_u32(&mut self, key: &str, value: u32) {
        self.write_key(key);
        self.write_u64(value as u64);
    }

    pub fn key_i64(&mut self, key: &str, value: i64) {
        self.write_key(key);
        if value < 0 {
            self.buf.push(b'-');
            self.write_u64((!value as u64).wrapping_add(1));
        } else {
            self.write_u64(value as u64);
        }
    }

    pub fn key_object(&mut self, key: &str) {
        self.write_key(key);
        self.buf.push(b'{');
        self.first = true;
    }

    fn write_u64(&mut self, mut value: u64) {
        if value == 0 {
            self.buf.push(b'0');
            return;
        }
        let mut digits = [0u8; 20];
        let mut i = 0;
        while value > 0 {
            digits[i] = b'0' + (value % 10) as u8;
            value /= 10;
            i += 1;
        } 
        while i > 0 {
            i -= 1;
            self.buf.push(digits[i]);
        }
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

// Minimal pull style JSON parser
pub struct JsonReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> JsonReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}