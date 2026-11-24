use super::*;

#[derive(Clone, serde::Serialize)]
pub(super) struct PilotBlock {
    pub(super) doc: usize,
    pub(super) id: u32,
    pub(super) offset: usize,
    pub(super) len: usize,
}
pub(super) fn db_ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.
}
