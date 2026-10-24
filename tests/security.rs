use rand::rngs::OsRng;
use tcw_mask::attack::{simulate_attack, AttackMode};
use tcw_mask::bundle::ShareBundle;
use tcw_mask::commitment::PedersenGenerators;
use tcw_mask::field::FieldElement;
use tcw_mask::sharing::split_secret;

#[test]
fn test_security_tamper_defense() {
    let mut rng = OsRng;
    let gens = PedersenGenerators::default();
    let master = FieldElement::from_u64(0xFEEDFACE);
    let raw_shares = split_secret(master, 3, 5, &mut rng).unwrap();

    let mut bundles = Vec::new();
    for (idx, share) in raw_shares.iter().enumerate() {
        bundles.push(ShareBundle::create(
            share,
            (idx + 1) as u32,
            3,
            5,
            "sec_sess",
            &gens,
            &mut rng,
        ));
    }

    let tamper_res = simulate_attack(&bundles, AttackMode::Tamper);
    assert!(tamper_res.detected);

    let insuf_res = simulate_attack(&bundles, AttackMode::Insufficient);
    assert!(insuf_res.detected);

    let replay_res = simulate_attack(&bundles, AttackMode::Replay);
    assert!(replay_res.detected);
}
