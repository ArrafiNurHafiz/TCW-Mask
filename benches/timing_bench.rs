use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use tcw_mask::field::FieldElement;
use tcw_mask::sharing::{reconstruct_secret, split_secret};

fn bench_tcw_mask(c: &mut Criterion) {
    let mut rng = OsRng;
    let a = FieldElement::from_u64(0x12345678);
    let b = FieldElement::from_u64(0x87654321);

    c.bench_function("field_mul", |bencher| {
        bencher.iter(|| black_box(a).mul(&black_box(b)))
    });

    c.bench_function("field_invert", |bencher| {
        bencher.iter(|| black_box(a).invert())
    });

    c.bench_function("split_3_of_5", |bencher| {
        bencher.iter(|| split_secret(black_box(a), 3, 5, &mut rng).unwrap())
    });

    let raw = split_secret(a, 3, 5, &mut rng).unwrap();
    let subset = &raw[..3];
    c.bench_function("reconstruct_3_of_5", |bencher| {
        bencher.iter(|| reconstruct_secret(black_box(subset), 3).unwrap())
    });
}

criterion_group!(benches, bench_tcw_mask);
criterion_main!(benches);
