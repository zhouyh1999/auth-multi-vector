use super::*;

pub(super) const BLOCK_POWER_METHOD: u8 = 5;
pub(super) fn block_weights_for_request(
    method: u8,
    case: &FairCase,
    binding: Hash,
) -> Result<Vec<Scalar>> {
    if method != BLOCK_POWER_METHOD || case.blocks.len() == 1 {
        return fair_weights(case, binding);
    }
    let mut transcript = merlin::Transcript::new(b"gem.block-power-aggregation.v1");
    transcript.append_message(b"profile", numeric::PROFILE_ID.as_bytes());
    transcript.append_message(b"statement-digest", &binding);
    transcript.append_u64(b"document-count", case.blocks.len() as u64);
    let z = loop {
        let candidate = gem_matrix_proof::challenge_scalar_v1(&mut transcript, b"block-power");
        if candidate != Scalar::ZERO {
            break candidate;
        }
        transcript.append_message(b"zero-retry", b"block-power");
    };
    u32::try_from(case.blocks.len()).map_err(|_| gem_core::GemError::InvalidTokenCount)?;
    Ok(geometric_sequence(
        z,
        case.blocks.len(),
        selected_power_kernel(method, false) != PowerKernel::Reference,
    ))
}
