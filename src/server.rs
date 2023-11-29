pub mod zkp_auth {
    include!("./zkp_auth.rs");
}
use std::collections::HashMap;
use std::sync::Mutex;
use tonic::Response;

use num_bigint::BigUint;
use zkp_auth::{auth_server::Auth, RegisterRequest, RegisterResponse, AuthenticationChallengeRequest, AuthenticationChallengeResponse, AuthenticationAnswerRequest, AuthenticationAnswerResponse};

pub struct AuthUser {
    user_info_map: Mutex<HashMap<String, UserData>>,
    auth_id_map: Mutex<HashMap<String, UserData>>,
}

#[derive(Debug, Default)]
pub struct UserData {
    user: String,
    y1: BigUint,
    y2: BigUint,
    r1: BigUint,
    r2: BigUint,
    k: BigUint,
    c: BigUint,
    s: BigUint,
    session_id: String,
}

#[tonic::async_trait]
impl Auth for AuthUser {
    async fn register(
        &self,
        request: tonic::Request<RegisterRequest>,
    ) -> std::result::Result<tonic::Response<RegisterResponse>, tonic::Status> {
        let req = request.into_inner();
        let user = req.user;
        let userData = UserData {
            user,
            y1: BigUint::from_bytes_be(&req.y1),
            y2: BigUint::from_bytes_be(&req.y2),
            ..Default::default()
        };
        let user_info_map = &mut self.user_info_map.lock().unwrap();
        user_info_map.insert(user, userData);

        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        request: tonic::Request<AuthenticationChallengeRequest>,
    ) -> std::result::Result<
        tonic::Response<AuthenticationChallengeResponse>,
        tonic::Status,
    > {}

    async fn verify_authentication(
        &self,
        request: tonic::Request<AuthenticationAnswerRequest>,
    ) -> std::result::Result<
        tonic::Response<AuthenticationAnswerResponse>,
        tonic::Status,
    >{}
}

#[tokio::main]
async fn main() {
    println!("Server UP");
}
