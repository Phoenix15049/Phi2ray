use std::io::{self, BufRead};

pub const LOG_BYTES: usize = 2_000;

/// Reads one line, retaining at most `limit` bytes and draining the rest through the newline.
/// The caller can display a truncated log or discard a truncated protocol frame.
pub fn read(reader: &mut impl BufRead, line: &mut Vec<u8>, limit: usize) -> io::Result<Option<bool>> {
    line.clear();
    let mut truncated = false;
    loop {
        let bytes = reader.fill_buf()?;
        if bytes.is_empty() {
            return Ok((!line.is_empty() || truncated).then_some(truncated));
        }
        let newline = bytes.iter().position(|&b| b == b'\n');
        let end = newline.unwrap_or(bytes.len());
        let keep = end.min(limit - line.len());
        line.extend_from_slice(&bytes[..keep]);
        truncated |= keep < end;
        reader.consume(end + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(truncated));
        }
    }
}

#[cfg(test)]
#[test]
fn retains_only_the_limit_without_losing_the_following_frame() {
    use std::io::BufReader;
    let mut input = vec![0xff; 100_000];
    input.extend_from_slice(b"\nnext\nunfinished");
    let mut reader = BufReader::with_capacity(12, &input[..]);
    let mut line = Vec::new();
    assert_eq!(read(&mut reader, &mut line, 8).unwrap(), Some(true));
    assert_eq!(line, [0xff; 8]);
    assert_eq!(read(&mut reader, &mut line, 8).unwrap(), Some(false));
    assert_eq!(line, b"next");
    assert_eq!(read(&mut reader, &mut line, 8).unwrap(), Some(true));
    assert_eq!(line, b"unfinish");
    assert_eq!(read(&mut reader, &mut line, 8).unwrap(), None);
}
