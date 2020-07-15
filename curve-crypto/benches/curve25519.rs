#[macro_use]
extern crate criterion;
extern crate curve25519_dalek;
extern crate curve_crypto;
extern crate rand_core;

use criterion::Criterion;

use rand_core::OsRng;

use curve_crypto::*;

fn bench_diffie_hellman(c: &mut Criterion) {
    let bob_private = PrivateKey::new(&mut OsRng);
    let bob_public = PublicKey::from(&bob_private);

    c.bench_function("diffie_hellman", move |b| {
        b.iter_with_setup(
            || PrivateKey::new(&mut OsRng),
            |alice_private| alice_private.dh(&bob_public),
        )
    });
}

criterion_group! {
    name = x25519_benches;
    config = Criterion::default();
    targets =
        bench_diffie_hellman,
}
criterion_main! {
    x25519_benches,
}
