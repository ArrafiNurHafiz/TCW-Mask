use tcw_mask::bench::run_tvla;

#[test]
fn test_tvla_leakage_assessment() {
    #[cfg(debug_assertions)]
    let iters = 500;
    #[cfg(not(debug_assertions))]
    let iters = 5000;

    let result = run_tvla(iters);
    println!("TVLA t-score: {:.4}", result.t_score);
    assert!(
        result.is_leakage_free,
        "TVLA t-score exceeded 4.5: t = {}",
        result.t_score
    );
}
