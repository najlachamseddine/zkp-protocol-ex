# zkp protocol: exponentiation and elliptic curve authentication

This is a client/server application for authentication based on exponentiation and elliptic curve.

# Authentication types

## Exponentiation

The library for the exponentiation is set in the `chaum_pedersen` module. It is represented by the structure `ZKPProtocol` which is supporting the public variables `p` (order of the group), `q` (order of the sub group), `g` and `h` (two random variables mod q).
The user keeps the secret/password and sends a solution `s` to a `challenge` received from the server. The server then verifies the solution given the public data in its possession. If successful, a `session_id` is sent back to the user.


## Elliptic curve

The library for the exponentiation is set in the `pedersen_elliptic_curve` module. This is using the `curve25519_dalek::ristretto::RistrettoPoint` to generate public points G and H on the curve. The first step is to compute a commitment from the client side `C = m * G + r * H mod p` where `m` is the secret and `r` is called the blinding factor.
The client then reveals `C`, and after opens the commitment by sending `m` and `r` to the server which is validating it by comparing `C` to the commitment it computes.
Two functions have been added to the proto to support the elliptic curve authentication:
```
rpc SendPedersenCommitment(PedersenCommitmentRequest) returns (PedersenCommitmentResponse) {}
rpc OpenCommitment(CommitmentOpeningRequest) returns (CommitmentOpeningResponse) {}
```

## API

The API consists of these functions:

```
// For both authentication types
async fn register(...){}

// For exponentiation type
async fn create_authentication_challenge(...){}
async fn verify_authentication(...){}

// For elliptic curve type
async fn send_pedersen_commitment(...){}
async fn open_commitment(...){}

```

# Local deployment

`Cargo` rust tool is used to build and run the package.

Running the `server` needs to execute the below command in the `local-deploy` repository.

```
sh server.sh
```

Or directly in the root of the project:
```
cargo clean
RUST_LOG=info cargo run --bin server
```

Running the `client` needs to execute the command below command in the `local-deploy` repository.

```
sh client.sh
```
Or directly in the root of the project:
```
cargo run --bin client -- --url "http://127.0.0.1:8080/"
```


The client side must be in an interactive mode with a UI supporting the API. For simplicity, the client will here execute the requests sequentially without external interaction. Entering the username for example could be done by asking the user to enter their name in a terminal and then read it on the client side.
On the client side, you can choose the type of authentication to run. This is done in the `client.rs` file, in the `main()` function which is simulating the user/interface behavior.

```
enum AuthType {
    Exponentiation,
    EllipticCurve,
}
```

 You will need to comment out one the line below in the `main()` function:

```  
// Choosing between Exponentiation or Elliptic curve authentication (uncomment one)
// let authentication_type = AuthType::Exponentiation;
let authentication_type = AuthType::EllipticCurve;
```

# Docker deployment

To run the client and the server in two different containers, you would need to run the docker compose by executing the command below in the root of the project:

```
sh docker-images.sh
```
The docker compose will create two services `protocolserver` and `protocolclient` in two different containers.

To see the logs run:
```
sudo docker logs protocolserver
sudo docker logs protocolclient
```
As the client is simulating a UI, the container will restart after each call to the `main()`


# Improvements

* More tests. The server can also be mocked with the mockall rust feature and using expectation for the returning functions.
* Better logging (info, error, warn)
* files for different types of authentication library can be added within a subfolder
* Use a client who is interacting 
* Write benchmark with multiple users connecting at the same time (cargo bench can be used) using tokio:spawn
* Test the bigUint value in the exponentiation authentication (function provided but not tested)
* Optimize the docker images (space, remove rust tools, source code)




