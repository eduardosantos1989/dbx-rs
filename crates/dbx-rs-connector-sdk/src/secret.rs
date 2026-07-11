pub struct ResolvedSecret {
    bytes: Vec<u8>,
}

impl ResolvedSecret {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for ResolvedSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResolvedSecret([REDACTED])")
    }
}

impl Drop for ResolvedSecret {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_is_redacted() {
        let secret = ResolvedSecret::new(b"not-for-logs".to_vec());

        assert_eq!(format!("{secret:?}"), "ResolvedSecret([REDACTED])");
        assert!(!format!("{secret:?}").contains("not-for-logs"));
    }
}
