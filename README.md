# zkp-protocol-ex

This is a client/server application for authentication based on exponentiation and elliptic curve.

# Local deployment

Running the server needs to execute the command below command in the `local-deploy` repository.

```
sudo sh server.sh
```

Running the client needs to execute the command below command in the `local-deploy` repository.

```
sudo sh client.sh
```

On the client side, you can choose the type of authentication to run. This is done in the `client.rs` file, in the main() function which is simulating the user/interface behavior.

```
enum AuthType {
    Exponentiation,
    EllipticCurve,
}
```

The client side must be in an interactive mode with a UI supporting the API. For simplicity, the client will here execute the requests sequentially without external interaction. Entering the username for example could be done by asking the user to enter their name in a terminal and then read it on the client side.
 You will need to comment out one the line below:


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


# Improvments

* More tests. The server can also be mocked with the mockall rust library and using expectation for the returning functions.
* Better logging
* files for different types of authentication library can be added within a subfolder
* Use a client who is interacting 
* Write benchmark with multiple users connecting at the same time (cargo bench can be used)
* Test the bigUint value in the exponentiation authentication (function provided but not tested)




