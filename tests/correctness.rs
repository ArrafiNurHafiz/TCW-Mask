use rand::rngs::OsRng;
use rand::RngCore;
use tcw_mask::bundle::ShareBundle;
use tcw_mask::commitment::PedersenGenerators;
use tcw_mask::field::FieldElement;
use tcw_mask::sharing::{reconstruct_secret, split_secret};

#[test]
fn test_end_to_end_correctness() {
    let mut rng = OsRng;
    let gens = PedersenGenerators::default();

    #[cfg(debug_assertions)]
    let iterations = 10;
    #[cfg(not(debug_assertions))]
    let iterations = 1000;

    for i in 0..iterations {
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        key_bytes[31] &= 0x7F;
        let master = FieldElement::from_bytes(&key_bytes);

        let k = 3;
        let n = 5;
        let raw_shares = split_secret(master, k, n, &mut rng).unwrap();

        let session_id = format!("session_iter_{}", i);
        let mut bundles = Vec::new();
        for (idx, share) in raw_shares.iter().enumerate() {
            bundles.push(ShareBundle::create(
                share,
                (idx + 1) as u32,
                k as u32,
                n as u32,
                &session_id,
                &gens,
                &mut rng,
            ));
        }

        // Verify all bundles
        for b in &bundles {
            assert!(b.verify_integrity(&gens).is_ok());
        }

        // Pick any 3 bundles: 0, 2, 4
        let chosen = vec![bundles[0].clone(), bundles[2].clone(), bundles[4].clone()];
        let mut reconstructed_raw = Vec::new();
        for b in &chosen {
            reconstructed_raw.push(b.extract_raw_share(&gens).unwrap());
        }

        let recovered = reconstruct_secret(&reconstructed_raw, k).unwrap();
        assert_eq!(recovered.expose_secret().canonical(), master.canonical());
    }
}
