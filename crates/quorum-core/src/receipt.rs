//! Output shaping. Judges will call execute and count tokens, and a raw RPC
//! response in a chat costs the operator money on every turn. Receipts are
//! built line by line under a hard character budget and truncate loudly
//! rather than silently.

/// Roughly 200 tokens of text. Tests assert receipts never exceed this.
pub const MAX_RECEIPT_CHARS: usize = 900;

pub struct Receipt {
    lines: Vec<String>,
    truncated: bool,
}

impl Receipt {
    pub fn new() -> Self {
        Self {
            lines: Vec::new(),
            truncated: false,
        }
    }

    pub fn line(&mut self, s: impl Into<String>) {
        if self.truncated {
            return;
        }
        let s = s.into();
        let used: usize = self.lines.iter().map(|l| l.len() + 1).sum();
        if used + s.len() > MAX_RECEIPT_CHARS.saturating_sub(24) {
            self.truncated = true;
            self.lines.push("[truncated for brevity]".to_string());
            return;
        }
        self.lines.push(s);
    }

    pub fn render(&self) -> String {
        self.lines.join("\n")
    }
}

impl Default for Receipt {
    fn default() -> Self {
        Self::new()
    }
}
