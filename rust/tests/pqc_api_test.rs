use ml_kem::MlKem768;
use rand_core::OsRng;

#[test]
fn test_ml_kem() {
    let (dk, ek) = ml_kem::MlKem768::generate(&mut OsRng);
    let (ct, ss1) = ek.encapsulate(&mut OsRng); // Maybe doesn't return Result
    let ss2 = dk.decapsulate(&ct);
    assert_eq!(ss1, ss2);
}
