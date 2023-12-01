pub mod zkp_auth {
    include!("./zkp_auth.rs");
}
use env_logger;
use std::env;
use log;
use num_bigint::BigUint;
use zkp_protocol_ex::chaum_pedersen::*;
use zkp_auth::{auth_client::AuthClient, RegisterRequest, AuthenticationChallengeRequest, AuthenticationAnswerRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    // Builder::new()
    //     .parse_env(&env::var("ZKP_PROTOCOL_LOG").unwrap_or_default())
    //     .init();
    log::info!("Client UP");
    log::debug!("Client UP");
    // register
    // challenge request
    // verify request
    

    let mut client = AuthClient::connect("http://127.0.0.1:8083").await?;
    let protocol = get_fixed_zkp_params();
    let user = "najla".to_string();
    let x_password = BigUint::from(3u32);
    let (y1, y2) = protocol.compute_public_pair(&x_password);
 
 // Register
 let request_register = tonic::Request::new(RegisterRequest{user: user.clone(), y1: y1.to_bytes_be(), y2:y2.to_bytes_be()});
 let _ = client.register(request_register).await?;

 let k = generate_random_value(&protocol.q);
 let (r1, r2) = protocol.compute_public_pair(&k);

 let request_challenge = tonic::Request::new(AuthenticationChallengeRequest{user: user.clone(), r1: r1.to_bytes_be(), r2:r2.to_bytes_be()});
let challenge_response = client.create_authentication_challenge(request_challenge).await?;

let challenge = challenge_response.into_inner();
let c = BigUint::from_bytes_be(&challenge.c);
let s = protocol.compute_solution_for_challenge(&k, &c, &x_password);

let request_auth = tonic::Request::new(AuthenticationAnswerRequest {auth_id: challenge.auth_id, s: s.to_bytes_be() });
let auth_response = client.verify_authentication(request_auth).await?;

 println!("Session ID {:#?}", auth_response.into_inner().session_id);
Ok(())
}
