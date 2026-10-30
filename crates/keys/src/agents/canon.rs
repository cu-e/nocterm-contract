//! Canonical layouts: a domain string, then every field with a big-endian `u32` length prefix.

pub(crate) struct Writer(Vec<u8>);

impl Writer {
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut writer = Self(Vec::with_capacity(256));
        writer.field(domain);
        writer
    }

    pub(crate) fn field(&mut self, bytes: &[u8]) -> &mut Self {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(bytes);
        self
    }

    pub(crate) fn u64(&mut self, value: u64) -> &mut Self {
        self.field(&value.to_be_bytes())
    }

    pub(crate) fn i64(&mut self, value: i64) -> &mut Self {
        self.field(&value.to_be_bytes())
    }

    pub(crate) fn list(&mut self, items: &[String]) -> &mut Self {
        self.u64(items.len() as u64);
        for item in items {
            self.field(item.as_bytes());
        }
        self
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Reads what [`Writer`] wrote; every failure is the same "not canonical".
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8], domain: &[u8]) -> Option<Self> {
        let mut reader = Self(bytes);
        (reader.field()? == domain).then_some(reader)
    }

    pub(crate) fn field(&mut self) -> Option<&'a [u8]> {
        let (len, rest) = self.0.split_first_chunk::<4>()?;
        let len = u32::from_be_bytes(*len) as usize;
        if rest.len() < len {
            return None;
        }
        let (field, rest) = rest.split_at(len);
        self.0 = rest;
        Some(field)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.field()?.try_into().ok()
    }

    pub(crate) fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_be_bytes)
    }

    pub(crate) fn i64(&mut self) -> Option<i64> {
        self.array().map(i64::from_be_bytes)
    }

    pub(crate) fn string(&mut self) -> Option<String> {
        String::from_utf8(self.field()?.to_vec()).ok()
    }

    pub(crate) fn list(&mut self, max: usize) -> Option<Vec<String>> {
        let count = usize::try_from(self.u64()?).ok().filter(|n| *n <= max)?;
        (0..count).map(|_| self.string()).collect()
    }

    pub(crate) fn end(self) -> Option<()> {
        self.0.is_empty().then_some(())
    }
}
