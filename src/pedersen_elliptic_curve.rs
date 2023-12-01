// https://findora.org/faq/crypto/pedersen-commitment-with-elliptic-curves/#:~:text=A%20Pedersen%20commitment%20is%20a,information%20at%20all%20about%20m.

use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;

pub struct ZKPEllipticCurve {
    // pedersen setup base points G and H
    pub g: RistrettoPoint,
    pub h: RistrettoPoint
}

impl ZKPEllipticCurve {

    pub fn pedersen_commit(&self, r: Scalar,  x_password: Scalar) -> RistrettoPoint {
        RistrettoPoint::multiscalar_mul(&[r, x_password], vec![self.g, self.h])      
    }

    pub fn commit(&self,  x_password: Scalar) -> (RistrettoPoint, Scalar, Scalar) {
        let r = random_blinding_factor();
        let commitment = self.pedersen_commit(r, x_password);
        (commitment, r, x_password)
    }

    pub fn verify_commitment(&self, commitment: RistrettoPoint, commitment_opening: Scalar,  x_password: Scalar) -> bool {
        let c = self.pedersen_commit(commitment_opening, x_password);
        c == commitment
    }

}

pub fn pedersen_setup_base_points() -> PedersenGens {
    // let g =  &constants::RISTRETTO_BASEPOINT_POINT;
    PedersenGens::default()
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
    fn test_with_fixed_k_c() {
        let pc_gens = PedersenGens::default();
    }
}
