pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use curve25519_dalek::{scalar::Scalar, RistrettoPoint};
use num_bigint::BigUint;
use std::env;
use zkp_auth::{
    auth_client::AuthClient, AuthenticationAnswerRequest, AuthenticationChallengeRequest,
    CommitmentOpeningRequest, PedersenCommitmentRequest, RegisterRequest,
};
use zkp_protocol_ex::{
    chaum_pedersen::*,
    pedersen_elliptic_curve::pedersen_setup_base_points,
};

enum AuthType {
    Exponentiation,
    EllipticCurve,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let url = format!("{}", &args[2].to_string());
    println!("URL {}", url.clone());
    let mut client = AuthClient::connect(url)
        .await
        .map_err(|e| e)
        .expect("Could not connect to the server");

    // For big number (not tested yet)
    // let protocol = generate_1024bit_group_with_160bit_constants();
    let protocol = get_fixed_zkp_params();
    let user = "USER_NAME".to_string();
    let x = 123624374743u64;
    let x_password = BigUint::from(x);
    let (y1, y2) = protocol.compute_public_pair(&x_password);

    println!("✅ Client registers");
    let request_register = tonic::Request::new(RegisterRequest {
        user: user.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    });
    let _ = client.register(request_register).await?;

    // Choosing between Exponentiation or Elliptic curve authentication (uncomment one)
    // let authentication_type = AuthType::Exponentiation;
    let authentication_type = AuthType::EllipticCurve;

    match authentication_type {
        AuthType::Exponentiation => {
            println!("Authentication type: exponentiation");
            println!("✅ Client requests a challenge");
            let k = generate_random_value(&protocol.q);
            let (r1, r2) = protocol.compute_public_pair(&k);

            let request_challenge = tonic::Request::new(AuthenticationChallengeRequest {
                user: user.clone(),
                r1: r1.to_bytes_be(),
                r2: r2.to_bytes_be(),
            });
            let challenge_response = client
                .create_authentication_challenge(request_challenge)
                .await?;

            let challenge = challenge_response.into_inner();
            let c = BigUint::from_bytes_be(&challenge.c);
            let s = protocol.compute_solution_for_challenge(&k, &c, &x_password);

            println!("✅ Client sends the solution to the challenge");
            let request_auth = tonic::Request::new(AuthenticationAnswerRequest {
                auth_id: challenge.auth_id,
                s: s.to_bytes_be(),
            });
            let auth_response = client.verify_authentication(request_auth).await?;

            println!("✅ Session ID {:#?}", auth_response.into_inner().session_id);
        }
        AuthType::EllipticCurve => {
            println!("Authentication type: elliptic curve");
            println!("✅ Client sends the commitment");
            let x_password = Scalar::from(x);
            let mut zkpelliptic = pedersen_setup_base_points();
            let (commitment, blinding_factor, secret) = zkpelliptic.commit(x_password);
            // println!("commitment client {:#?}",  commitment);
            let compressed_commitment = RistrettoPoint::compress(&commitment).to_bytes().to_vec();
            let request_set_commitment = tonic::Request::new(PedersenCommitmentRequest {
                user: user.clone(),
                compressed_commitment: compressed_commitment.clone(),
            });
            // println!("{:#?}", compressed_commitment.clone());
            let set_commitment_response = client
                .send_pedersen_commitment(request_set_commitment)
                .await?;
            let commitment_response = set_commitment_response.into_inner();

            println!("✅ Client opens the commitment");
            let request_commitment_opening = tonic::Request::new(CommitmentOpeningRequest {
                auth_id: commitment_response.auth_id,
                r: blinding_factor.to_bytes().to_vec(),
                m: secret.to_bytes().to_vec(),
            });
            // println!("blinding {:#?}",  blinding_factor);
            // println!("secret {:#?}",  secret);
            let commitment_opening_response =
                client.open_commitment(request_commitment_opening).await?;

            println!(
                "✅ Session ID {:#?}",
                commitment_opening_response.into_inner().session_id
            );
        }
        _ => println!("Unknown authentication type"),
    }
    Ok(())
}
