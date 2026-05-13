use std::fmt::{self, Write};

struct LimitedWriter<'a> {
    target: &'a mut String,
    remaining: usize,
    truncated: bool,
}

impl Write for LimitedWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.remaining == 0 {
            self.truncated = true;
            return Err(fmt::Error);
        }

        if s.len() <= self.remaining {
            self.target.push_str(s);
            self.remaining -= s.len();
            return Ok(());
        }

        let mut end = self.remaining;

        while !s.is_char_boundary(end) {
            end -= 1;
        }

        self.target.push_str(&s[..end]);
        self.remaining = 0;
        self.truncated = true;

        Err(fmt::Error)
    }
}

pub fn truncate_debug(data: &impl std::fmt::Debug, limit: usize) -> String {
    const SUFFIX: &str = "...";

    if limit == 0 {
        return String::new();
    }

    let content_limit = limit.saturating_sub(SUFFIX.len());

    let mut buf = String::with_capacity(limit);
    let mut writer = LimitedWriter {
        target: &mut buf,
        remaining: content_limit,
        truncated: false,
    };

    let _ = write!(&mut writer, "{:?}", data);

    if writer.truncated {
        buf.push_str(SUFFIX);
    }

    buf
}
