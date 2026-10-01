//! Monotonic age belongs to a completed sample, never to a cache read.
use std::collections::BTreeSet;
#[derive(Debug, Default)]
pub struct Freshness {
    epoch: Option<(String, String)>,
    retired: BTreeSet<(String, String)>,
    generation: Option<u64>,
    digest: String,
    accepted_ms: u64,
    age_ms: u64,
    pub conflicted: bool,
    pub distinct: u64,
}
impl Freshness {
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        process: &str,
        source: &str,
        generation: u64,
        digest: &str,
        now: u64,
        source_age: u64,
        request_duration: u64,
    ) -> Result<bool, &'static str> {
        if process.is_empty()
            || source.is_empty()
            || process.len() > 128
            || source.len() > 128
            || !crate::wire::hash(digest)
        {
            return Err("invalid source identity");
        }
        let age = source_age.checked_add(request_duration).ok_or("age overflow")?;
        let epoch = (process.to_owned(), source.to_owned());
        if self.epoch.as_ref() != Some(&epoch) {
            if self.retired.contains(&epoch) {
                return Err("retired epoch");
            }
            if self.retired.len() >= 32 {
                return Err("epoch budget exhausted");
            }
            if let Some(old) = self.epoch.replace(epoch) {
                self.retired.insert(old);
            }
            self.generation = None;
            self.conflicted = false;
            self.distinct = 0;
        } else if now < self.accepted_ms {
            return Err("monotonic clock reversed");
        }
        if self.generation == Some(generation) {
            if self.digest != digest {
                self.conflicted = true;
                return Err("SOURCE_CONFLICT");
            }
            return Ok(false);
        }
        if self.generation.is_some_and(|g| generation < g) {
            return Ok(false);
        }
        let next = self.distinct.checked_add(1).ok_or("distinct overflow")?;
        self.generation = Some(generation);
        self.digest = digest.into();
        self.accepted_ms = now;
        self.age_ms = age;
        self.distinct = next;
        Ok(true)
    }
    pub fn usable(&self, now: u64, ttl: u64) -> bool {
        self.generation.is_some()
            && !self.conflicted
            && now
                .checked_sub(self.accepted_ms)
                .and_then(|d| self.age_ms.checked_add(d))
                .is_some_and(|a| a <= ttl)
    }
    pub fn age(&self, now: u64) -> Option<u64> {
        self.generation?;
        now.checked_sub(self.accepted_ms).and_then(|elapsed| self.age_ms.checked_add(elapsed))
    }
}
