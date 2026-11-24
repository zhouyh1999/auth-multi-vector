use bulletproofs::SpringLinearProof;
use merlin::Transcript;

#[test]
fn merlin_matches_pristine_3_0_0_across_rate_boundaries() {
    let mut transcript = Transcript::new(b"auth-gem.regression");
    let message: Vec<_> = (0..1024usize).map(|i| (i * 37 + i / 7) as u8).collect();
    transcript.append_message(b"input", &message);
    transcript.append_u64(b"rows", 128);
    let mut challenge = [0; 64];
    transcript.challenge_bytes(b"challenge", &mut challenge);
    // Produced with the pristine reference/strobe.rs from the pinned Merlin distribution.
    assert_eq!(hex::encode(challenge), concat!(
        "d3ac9385fa8177b7b68f54bbb837cddf2f83bc77f016bc52cf42e779483fa2e3",
        "4b832b1a8cdfc0f3faf780d38dd6aa0218168c26823e21ebea597ad03a35a792"));
}

#[test]
fn spring_dimension_bound_encoding_at_128() {
    // Existing IPA dimension_bound_parser_rejects_wrong_round_count_and_invalid_points vector.
    let mut encoded = vec![0u8; 544];
    assert!(SpringLinearProof::from_bytes_for_dimension(&encoded, 128).is_ok());
    assert!(SpringLinearProof::from_bytes_for_dimension(&encoded[..480], 128).is_err());
    encoded[..32].fill(0xff);
    assert!(SpringLinearProof::from_bytes_for_dimension(&encoded, 128).is_err());
}

