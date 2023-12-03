pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use curve25519_dalek::RistrettoPoint;
use log::info;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Mutex;
use tonic::{transport::Server, Code, Response, Status};
use zkp_protocol_ex::chaum_pedersen::*;

use num_bigint::BigUint;
use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, CommitmentOpeningRequest, CommitmentOpeningResponse,
    PedersenCommitmentRequest, PedersenCommitmentResponse, RegisterRequest, RegisterResponse,
};
use zkp_protocol_ex::pedersen_elliptic_curve::{ZKPEllipticCurve, pedersen_setup_base_points};
use sha3::Sha3_512;
use curve25519_dalek::Scalar;
use sha2::Sha512;

#[derive(Default)]
pub struct AuthUser {
    user_info_map: Mutex<HashMap<String, UserData>>,
    auth_id_map: Mutex<HashMap<String, String>>,
}

#[derive(Clone, Debug, Default)]
pub struct UserData {
    user: String,
    y1: BigUint,
    y2: BigUint,
    r1: BigUint,
    r2: BigUint,
    // k: BigUint,
    c: BigUint,
    s: BigUint,
    pedersen_commitment: RistrettoPoint,
    session_id: String,
}

#[tonic::async_trait]
impl Auth for AuthUser {
    async fn register(
        &self,
        request: tonic::Request<RegisterRequest>,
    ) -> std::result::Result<tonic::Response<RegisterResponse>, tonic::Status> {
        let req_data = request.into_inner();
        let user = req_data.user;
        info!("Register user {}", user);
        let user_data = UserData {
            user: user.clone(),
            y1: BigUint::from_bytes_be(&req_data.y1),
            y2: BigUint::from_bytes_be(&req_data.y2),
            ..Default::default()
        };
        let user_info_map = &mut self.user_info_map.lock().unwrap();
        if user_info_map.get(&user).is_none() {
        user_info_map.insert(user, user_data);
        }

        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        request: tonic::Request<AuthenticationChallengeRequest>,
    ) -> std::result::Result<tonic::Response<AuthenticationChallengeResponse>, tonic::Status> {
        let req_data = request.into_inner();
        let user = req_data.user;
        info!("Exponentiation auth: create authentication challenge for user {}", user);
        let user_info_map = &mut self.user_info_map.lock().unwrap();
        if let Some(user_data) = user_info_map.get_mut(&user) {
            let protocol = get_fixed_zkp_params();
            let challenge = generate_random_value(&protocol.q);
            user_data.r1 = BigUint::from_bytes_be(&req_data.r1);
            user_data.r2 = BigUint::from_bytes_be(&req_data.r2);
            user_data.c = challenge.clone();
            let auth_id = create_random_string();
            let auth_id_map = &mut self.auth_id_map.lock().unwrap();
            auth_id_map.insert(auth_id.clone(), user);
            Ok(Response::new(AuthenticationChallengeResponse {
                auth_id,
                c: challenge.to_bytes_be(),
            }))
        } else {
            Err(Status::new(
                Code::NotFound,
                format!("User: {} not found in database", user),
            ))
        }
    }

    async fn verify_authentication(
        &self,
        request: tonic::Request<AuthenticationAnswerRequest>,
    ) -> std::result::Result<tonic::Response<AuthenticationAnswerResponse>, tonic::Status> {
        let req = request.into_inner();
        let s = req.s;
        let auth_id = req.auth_id;
        info!("Exponentiation auth: verify authentication for auth_id {}", auth_id);
        let auth_id_map = self.auth_id_map.lock().unwrap();
        if let Some(u) = auth_id_map.get(&auth_id) {
            let user_info_map = &mut self.user_info_map.lock().unwrap();
            if let Some(user_data) = user_info_map.get_mut(u) {
                let protocol = get_fixed_zkp_params();
                let verified = protocol.verify_solution(
                    &user_data.c,
                    &BigUint::from_bytes_be(&s),
                    &user_data.r1,
                    &user_data.r2,
                    &user_data.y1,
                    &user_data.y2,
                );
                if !verified {
                    return Err(Status::new(
                        Code::NotFound,
                        format!("Challenge error: {} not found in database", u),
                    ));
                }
                let session_id = create_random_string();
                user_data.session_id = session_id.clone();
                Ok(Response::new(AuthenticationAnswerResponse { session_id }))
            } else {
                Err(Status::new(
                    Code::NotFound,
                    format!("User with a: {} not found in database", u),
                ))
            }
        } else {
            Err(Status::new(
                Code::Unauthenticated,
                format!("Authentication ID: {} not found in database", auth_id),
            ))
        }
    }
    async fn send_pedersen_commitment(
        &self,
        request: tonic::Request<PedersenCommitmentRequest>,
    ) -> std::result::Result<tonic::Response<PedersenCommitmentResponse>, tonic::Status> {
        let req_data = request.into_inner();
        let user = req_data.user;
        info!("Elliptic auth: user {} sends pedersen commitment", user);
        let commitment = req_data.compressed_commitment;
        let user_info_map = &mut self.user_info_map.lock().unwrap();
        if let Some(user_data) = user_info_map.get_mut(&user) {
            user_data.pedersen_commitment = RistrettoPoint::hash_from_bytes::<Sha3_512>(&commitment);
            let auth_id = create_random_string();
            return Ok(Response::new(PedersenCommitmentResponse { auth_id }));
        }
        Err(Status::new(
            Code::NotFound,
            format!("User with a: {} not found in database", user),
        ))
    }

    async fn open_commitment(
        &self,
        request: tonic::Request<CommitmentOpeningRequest>,
    ) -> std::result::Result<tonic::Response<CommitmentOpeningResponse>, tonic::Status> {
        let req = request.into_inner();
        let auth_id = req.auth_id;
        let r = req.r;
        let m = req.m;
        info!("Exponentiation auth: user with auth_id {} opens the commitment", auth_id);
        let auth_id_map = self.auth_id_map.lock().unwrap();
        if let Some(u) = auth_id_map.get(&auth_id) {
            let user_info_map = &mut self.user_info_map.lock().unwrap();
            if let Some(user_data) = user_info_map.get_mut(u) {
                let pc_gens = pedersen_setup_base_points();
                let zkpelliptic = ZKPEllipticCurve {
                    g: pc_gens.g,
                    h: pc_gens.h,
                };
                let verified = zkpelliptic.verify_commitment(user_data.pedersen_commitment, Scalar::hash_from_bytes::<Sha512>(&r), Scalar::hash_from_bytes::<Sha512>(&m));
                if !verified {
                    return Err(Status::new(
                        Code::PermissionDenied,
                        format!("Error while validating the commitment"),
                    ));
                }
                let session_id = create_random_string();
                user_data.session_id = session_id.clone();
                return Ok(Response::new(CommitmentOpeningResponse { session_id }));
            }
            return Err(Status::new(
                Code::Unauthenticated,
                format!("Authentication ID: {} not found in database", auth_id),
            ));
        }
            else {
                Err(Status::new(
                    Code::Unauthenticated,
                    format!("Authentication ID: {} not found in database", auth_id),
                ))
        }
    }
}

pub fn create_random_string() -> String {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();
    rand_string
}

impl Deref for UserData {
    type Target = UserData;
    fn deref(&self) -> &Self::Target {
        self
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("Running the server");
    let address = "127.0.0.1:8080".parse().expect("Wrong server url");
    let auth_user = AuthUser::default();
    Server::builder()
        .add_service(AuthServer::new(auth_user))
        .serve(address)
        .await
        .map_err(|e| e)
        .expect("Could not start the server");
    Ok(())
}
