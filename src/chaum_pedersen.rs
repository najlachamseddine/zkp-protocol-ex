// https://github.com/topics/chaum-pedersen
// https://crypto.stackexchange.com/questions/99262/chaum-pedersen-protocol
// group quotient Z/23
// sub group cyclic (23 - 1 / 2) => Q = Z/11
// choose g and h in Q

use num_bigint::{BigUint, RandBigInt};
use rand::Rng;

pub struct ZKPProtocol {
    /// a large prime order exp: Z/pZ
    pub p: BigUint,
    /// A prime order sub group Z/qZ  (q = (p- 1)/2)
    pub q: BigUint,
    /// A generator of Z/qZ
    pub g: BigUint,
    /// A generator of Z/qZ
    pub h: BigUint,
}

impl ZKPProtocol {
    ///
    /// compute the public information from g, h and the secret password x (done on the prover side)
    /// y1 = g^x mode p and y2 = h^x mod p
    ///
    pub fn compute_public_pair(&self, x: &BigUint) -> (BigUint, BigUint) {
        (self.g.modpow(x, &self.p), self.h.modpow(x, &self.p))
    }

    ///
    /// solve the challenge c send by the server
    /// k random in Z/qZ generated by the prover
    /// c random in Z/qZ generated byt the server
    ///
    pub fn compute_solution_for_challenge(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
        if *k > c * x {
            return k - c * x.modpow(&BigUint::from(1u32), &self.q);
        }
        &self.q - (c * x - k).modpow(&BigUint::from(1u32), &self.q)
    }

    ///
    /// Verify the solution server side
    /// r1 = g^k mod p = (g^s mod p * y1^c mod p) mod p
    /// r2 = h^k mod p = (h^s mod p * y2^c mod p) mod p
    ///
    pub fn verify_solution(
        &self,
        c: &BigUint,
        s: &BigUint,
        r1: &BigUint,
        r2: &BigUint,
        y1: &BigUint,
        y2: &BigUint,
    ) -> bool {
        (*r1 == ((self.g.modpow(s, &self.p)) * y1.modpow(c, &self.p))
            .modpow(&BigUint::from(1u32), &self.p))
            && (*r2
                == ((self.h.modpow(s, &self.p)) * y2.modpow(c, &self.p))
                    .modpow(&BigUint::from(1u32), &self.p))
    }
}

///
/// generate random value in Z/qZ
///
pub fn generate_random_value(max: &BigUint) -> BigUint {
    let mut rng = rand::thread_rng();
    rng.gen_biguint_below(max)
}

pub fn get_fixed_zkp_params() -> ZKPProtocol {
    return ZKPProtocol {
        p: BigUint::from(23u32),
        q: BigUint::from(11u32),
        g: BigUint::from(4u32),
        h: BigUint::from(9u32),
    };
}

// https://datatracker.ietf.org/doc/html/rfc5114
// pub fn generate_1024bit_group_with_160bit_constants() -> ZKPProtocol {
//     // The prime
//     let p = BigUint::from_bytes_be(&hex::decode("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371").unwrap());

//     // The generator
//     let g = BigUint::from_bytes_be(&hex::decode("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5").unwrap());

//     // The generator generates a prime-order subgroup of size:
//     let q =
//         BigUint::from_bytes_be(&hex::decode("F518AA8781A8DF278ABA4E7D64B7CB9D49462353").unwrap());

//     // Another generator:
//     // h = g^i, where i == 266FEA1E5C41564B777E69
//     let i = BigUint::from_bytes_be(&hex::decode("266FEA1E5C41564B777E69").unwrap());
//     let h = g.modpow(&i, &p);

//     ZKPProtocol { p, q, g, h }
// }

// pub fn generate_2048bit_group_with_256bit_constants() -> ZKPProtocol {
//     // The prime
//     let p = BigUint::from_bytes_be(&hex::decode("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597").unwrap());

//     // The generator
//     let g = BigUint::from_bytes_be(&hex::decode("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659").unwrap());

//     // The generator generates a prime-order subgroup of size:
//     let q = BigUint::from_bytes_be(
//         &hex::decode("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3").unwrap(),
//     );

//     // Another generator:
//     // h = g^i, where i == 266FEA1E5C41564B777E69
//     let i = BigUint::from_bytes_be(&hex::decode("266FEA1E5C41564B777E69").unwrap());
//     let h = g.modpow(&i, &p);

//     ZKPProtocol { p, q, g, h }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_fixed_k_c() {
        let params = ZKPProtocol {
            p: BigUint::from(23u32),
            q: BigUint::from(11u32),
            g: BigUint::from(4u32),
            h: BigUint::from(9u32),
        };

        let x = BigUint::from(3u32);
        let k = BigUint::from(4u32);

        let (y1, y2) = params.compute_public_pair(&x);
        assert_eq!(y1, BigUint::from(18u32));
        assert_eq!(y2, BigUint::from(16u32));

        let (r1, r2) = params.compute_public_pair(&k);
        assert_eq!(r1, BigUint::from(3u32));
        assert_eq!(r2, BigUint::from(6u32));

        let c = BigUint::from(2u32);

        let s = params.compute_solution_for_challenge(&k, &c, &x);
        assert_eq!(s, BigUint::from(9u32));

        let verified = params.verify_solution(&c, &s, &r1, &r2, &y1, &y2);
        assert!(verified);
    }

    #[test]
    fn test_with_random_k_c() {
        let params = ZKPProtocol {
            p: BigUint::from(23u32),
            q: BigUint::from(11u32),
            g: BigUint::from(4u32),
            h: BigUint::from(9u32),
        };

        let x = BigUint::from(3u32);
        let k = generate_random_value(&params.q);

        let (y1, y2) = params.compute_public_pair(&x);
        assert_eq!(y1, BigUint::from(18u32));
        assert_eq!(y2, BigUint::from(16u32));

        let (r1, r2) = params.compute_public_pair(&k);
        let c = generate_random_value(&params.q);
        let s = params.compute_solution_for_challenge(&k, &c, &x);

        let verified = params.verify_solution(&c, &s, &r1, &r2, &y1, &y2);
        assert!(verified);
    }
}
