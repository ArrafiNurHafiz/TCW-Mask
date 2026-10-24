use crate::bundle::ShareBundle;
use crate::commitment::PedersenGenerators;
use crate::field::FieldElement;
use crate::polynomial::Polynomial;
use crate::sharing::RawShare;
use rand::RngCore;

pub fn refresh_shares<R: RngCore>(
    bundles: &[ShareBundle],
    gens: &PedersenGenerators,
    rng: &mut R,
) -> Result<Vec<ShareBundle>, String> {
    if bundles.is_empty() {
        return Err("No share bundles provided for refresh".to_string());
    }

    let k = bundles[0].threshold as usize;
    let n = bundles[0].total_shares as usize;

    if bundles.len() < k {
        return Err(format!(
            "Refreshing requires at least threshold k={} shares, got {}",
            k,
            bundles.len()
        ));
    }

    // Generate zero-polynomial g(x) where g(0) = 0
    let zero_poly = Polynomial::random(FieldElement::ZERO, k - 1, rng);

    // Generate fresh epoch session_id
    let mut session_bytes = [0u8; 16];
    rng.fill_bytes(&mut session_bytes);
    let new_session_id = format!("epoch_{}", hex::encode(session_bytes));

    let mut refreshed_bundles = Vec::with_capacity(bundles.len());

    for bundle in bundles {
        let raw = bundle.extract_raw_share(gens)?;
        let delta = zero_poly.evaluate(raw.x);
        let new_y = raw.y.add(&delta);

        let refreshed_raw = RawShare { x: raw.x, y: new_y };

        let new_bundle = ShareBundle::create(
            &refreshed_raw,
            bundle.index,
            k as u32,
            n as u32,
            &new_session_id,
            gens,
            rng,
        );
        refreshed_bundles.push(new_bundle);
    }

    Ok(refreshed_bundles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharing::{reconstruct_secret, split_secret};
    use rand::rngs::OsRng;

    #[test]
    fn test_proactive_refresh_preserves_secret() {
        let mut rng = OsRng;
        let gens = PedersenGenerators::default();
        let master = FieldElement::from_u64(0xCAFE_BABE);
        let raw_shares = split_secret(master, 3, 5, &mut rng).unwrap();

        let session_1 = "epoch_1";
        let mut bundles_epoch1 = Vec::new();
        for (i, s) in raw_shares.iter().enumerate() {
            bundles_epoch1.push(ShareBundle::create(
                s,
                (i + 1) as u32,
                3,
                5,
                session_1,
                &gens,
                &mut rng,
            ));
        }

        // Refresh all shares to epoch 2
        let bundles_epoch2 = refresh_shares(&bundles_epoch1, &gens, &mut rng).unwrap();
        assert_eq!(bundles_epoch2.len(), 5);
        assert_ne!(bundles_epoch2[0].session_id, session_1);

        // Verify epoch 2 shares
        for b in &bundles_epoch2 {
            assert!(b.verify_integrity(&gens).is_ok());
        }

        // Reconstruct from epoch 2 shares (shares 1, 3, 4)
        let chosen_epoch2 = vec![
            bundles_epoch2[0].clone(),
            bundles_epoch2[2].clone(),
            bundles_epoch2[3].clone(),
        ];
        let mut rec_raw = Vec::new();
        for b in &chosen_epoch2 {
            rec_raw.push(b.extract_raw_share(&gens).unwrap());
        }

        let recovered = reconstruct_secret(&rec_raw, 3).unwrap();
        assert_eq!(recovered.expose_secret().canonical(), master.canonical());

        // Incompatible mix: 2 shares from epoch 1 + 1 share from epoch 2 must fail or produce incorrect secret
        let mixed = vec![
            bundles_epoch1[0].extract_raw_share(&gens).unwrap(),
            bundles_epoch1[1].extract_raw_share(&gens).unwrap(),
            bundles_epoch2[2].extract_raw_share(&gens).unwrap(),
        ];
        let bad_rec = reconstruct_secret(&mixed, 3).unwrap();
        assert_ne!(bad_rec.expose_secret().canonical(), master.canonical());
    }
}
