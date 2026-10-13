//! Reads that cannot outgrow their limit.
//!
//! A length taken from `metadata()` is advisory: the file can grow after the check, and special
//! files report a length of zero. Every whole-file read in this crate goes through here, which
//! reads at most `max + 1` bytes and reports when the limit was crossed.

use std::io::Read;

pub enum Bounded {
    Complete(Vec<u8>),
    /// The source holds more than `max` bytes.
    TooLarge,
}

pub fn read_bounded(source: impl Read, max: u64) -> std::io::Result<Bounded> {
    let mut data = Vec::new();
    source.take(max.saturating_add(1)).read_to_end(&mut data)?;
    if data.len() as u64 > max {
        Ok(Bounded::TooLarge)
    } else {
        Ok(Bounded::Complete(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader that never ends, like /dev/zero or a file that keeps growing.
    struct Endless;

    impl Read for Endless {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            buffer.fill(0);
            Ok(buffer.len())
        }
    }

    #[test]
    fn an_endless_source_stops_at_the_limit() {
        assert!(matches!(read_bounded(Endless, 1000).unwrap(), Bounded::TooLarge));
    }

    #[test]
    fn a_source_exactly_at_the_limit_is_complete() {
        match read_bounded(&[7u8; 1000][..], 1000).unwrap() {
            Bounded::Complete(data) => assert_eq!(data.len(), 1000),
            Bounded::TooLarge => panic!("1000 bytes fit a limit of 1000"),
        }
        assert!(matches!(read_bounded(&[7u8; 1001][..], 1000).unwrap(), Bounded::TooLarge));
    }
}
