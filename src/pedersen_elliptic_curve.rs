// https://findora.org/faq/crypto/pedersen-commitment-with-elliptic-curves/#:~:text=A%20Pedersen%20commitment%20is%20a,information%20at%20all%20about%20m.

// use bulletproofs::PedersenGens;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand_core::OsRng;
use sha3::Sha3_512;

// https://doc-internal.dalek.rs/src/bulletproofs/generators.rs.html#28-33
#[derive(Debug)]
pub struct ZKPEllipticCurve {
    // pedersen setup base points G and H
    // we can also use directly the type PedersenGens instead of breaking it down and call commit p.commit on PedersenGens
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
}

impl ZKPEllipticCurve {
    pub fn pedersen_commit(&self, value: Scalar, blinding: Scalar) -> RistrettoPoint {
        RistrettoPoint::multiscalar_mul(&[value, blinding], &[self.g, self.h])
    }

    pub fn commit(&mut self, x_password: Scalar) -> (RistrettoPoint, Scalar, Scalar) {
        let r = random_blinding_factor();
        let commitment = self.pedersen_commit(x_password, r);
        (commitment, r, x_password)
    }

    pub fn verify_commitment(
        &self,
        commitment: RistrettoPoint,
        commitment_opening: Scalar,
        x_password: Scalar,
    ) -> bool {
        let c = self.pedersen_commit( x_password, commitment_opening);
        // println!("--------commitment COMPUTED {:#?}",  c);
        // println!("--------commitment STORED {:#?}",  commitment);
        c == commitment
    }
}

impl Default for ZKPEllipticCurve {
    fn default() -> Self {
        ZKPEllipticCurve {
            g: RISTRETTO_BASEPOINT_POINT,
            h: RistrettoPoint::hash_from_bytes::<Sha3_512>(
                RISTRETTO_BASEPOINT_COMPRESSED.as_bytes(),
            ),
        }
    }
}

pub fn pedersen_setup_base_points() -> ZKPEllipticCurve {
    ZKPEllipticCurve::default()
}

pub fn create_pedersen_g_h_points() -> (RistrettoPoint, RistrettoPoint) {
    let g = constants::RISTRETTO_BASEPOINT_POINT;
    let mut csprng = OsRng;
    let a = Scalar::random(&mut csprng);
    let h = a * g;
    (g, h)
}

pub fn random_blinding_factor() -> Scalar {
    let mut csprng = OsRng;
    Scalar::random(&mut csprng)
}

pub fn value_to_scalar(x_password: u64) -> Scalar {
    Scalar::from(x_password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_elliptic() {
        let x_password = Scalar::from(124253u64);
        let g = constants::RISTRETTO_BASEPOINT_POINT;
        let mut csprng = OsRng;
        let a = Scalar::random(&mut csprng);
        let h = a * g;

        // let p = pedersen_setup_base_points();

        let mut zkpelliptic = ZKPEllipticCurve { g, h };

        let (commitment, r, x) = zkpelliptic.commit(x_password);

        let verified = zkpelliptic.verify_commitment(commitment, r, x);
        assert!(verified);
    }
}
