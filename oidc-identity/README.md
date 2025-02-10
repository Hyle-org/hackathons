# OIDC Identity Authentication App

This project provides an OpenID Connect (OIDC) authentication system that supports multiple identity providers. It allows users to authenticate using various OIDC providers such as **Google, Auth0** etc., with flexible configuration via `config.toml` and secrets stored securely in an `.env` file.

## **Prerequisites**

- [Install Rust](https://www.rust-lang.org/tools/install) (requires `rustup` and Cargo).
- Install **RISC Zero** (if using a RISC Zero verifier).
- Ensure you have an **OIDC identity provider** set up (e.g., Google, GitHub, or Auth0).
- Create an `.env` file to store sensitive credentials securely.

---

## **Configuration Setup**

### **🔧 Environment Variables (`.env` File)**

To keep client secrets secure, store them in an `.env` file in the root directory:

```ini
# .env file
OIDC_[PROVIDER]__CLIENT_SECRET=your_oidc_client_secret_here
```

### **🔧 Configuring Identity Providers (`config.toml` File)**

Define the **identity providers** and application settings in `config.toml`:

```toml
[contract]
name = "oidc_identity"

[server]
host = "http://localhost:4321"
server = "http://localhost:8000"

[identity_providers]
[identity_providers.google]
issuer_url = "https://accounts.google.com"
audience_url = "https://myapp.example.com"
client_secret = "your_google_client_secret"
jwk_public_key_url = "https://www.googleapis.com/oauth2/v3/certs"

[identity_providers.auth0]
issuer_url = "https://your-auth0-domain.com/"
audience_url = "https://api.example.com"
client_secret = "your_auth0_client_secret"
jwk_public_key_url = "https://your-auth0-domain.com/.well-known/jwks.json"
```

---

## **Quickstart**

### **1️⃣ Register the OIDC Identity Contract**

Run the following command to register the identity contract on the local node:

```sh
cargo run -- register-contract
```

### **2️⃣ Authenticate Using an OIDC Provider**

To authenticate a user using Google:

```sh
cargo run -- register-identity --provider google
```

Expected output:

```sh
Waiting for OpenID provider to redirect with the access code...
```

Then you open the url and the client automatically receives the auth code from the google oidc provider and proceeds to follow the authentication sequence.

### Verify identity / Login

To verify user identity:

```sh
cargo run -- verify-identity --provider google
```

This also follows the authentication sequence

### Authentication Sequence

- Extract the header, payload, and signature from the JWT.
- Decode the signature using Base64-URL decoding.
- Compute the hash of the header.payload using the specified algorithm (e.g., RS256 → SHA256).
- Verify the signature using the public key from the OIDC provider's JWK.
- Upon successful verification, the system will:
- Validate the issuer (iss) and audience (aud) claims.
- Ensure the JWT has not expired.
- Return the decoded claims for further processing.

---

### Executing the Project Locally in Development Mode

During development, faster iteration upon code changes can be achieved by leveraging [dev-mode], we strongly suggest activating it during your early development phase. Furthermore, you might want to get insights into the execution statistics of your project, and this can be achieved by specifying the environment variable `RUST_LOG="[executor]=info"` before running your project.

Put together, the command to run your project in development mode while getting execution statistics is:

```bash
RUST_LOG="[executor]=info" RISC0_DEV_MODE=1 cargo run
```

<!--### Running Proofs Remotely on Bonsai-->
<!---->
<!--_Note: The Bonsai proving service is still in early Alpha; an API key is-->
<!--required for access. [Click here to request access][bonsai access]._-->
<!---->
<!--If you have access to the URL and API key to Bonsai you can run your proofs-->
<!--remotely. To prove in Bonsai mode, invoke `cargo run` with two additional-->
<!--environment variables:-->
<!---->
<!--```bash-->
<!--BONSAI_API_KEY="YOUR_API_KEY" BONSAI_API_URL="BONSAI_URL" cargo run-->
<!--```-->

## How to create a project based on this example

- The [RISC Zero Developer Docs][dev-docs] is a great place to get started.
- Example projects are available in the [examples folder][examples] of
  [`risc0`][risc0-repo] repository.
- Reference documentation is available at [https://docs.rs][docs.rs], including
  [`risc0-zkvm`][risc0-zkvm], [`cargo-risczero`][cargo-risczero],
  [`risc0-build`][risc0-build], and [others][crates].

## Directory Structure

It is possible to organize the files for these components in various ways.
However, in this starter template we use a standard directory structure for zkVM
applications, which we think is a good starting point for your applications.

```text
project_name
├── Cargo.toml
├── contract 
│   ├── Cargo.toml
│   └── src
│       ├── jwt.rs         <-- [Jwt authentication]
│       └── lib.rs         <-- [Contract code, common to host & guest]
├── host
│   ├── Cargo.toml
│   └── src
│       └── main.rs        <-- [Host code]
├── methods
│    ├── Cargo.toml
│    ├── build.rs
│    ├── guest
│    │   ├── Cargo.toml
│    │   └── src
│    │       └── main.rs    <-- [Guest code]
│    └── src
│        └── lib.rs
└── provider
    ├── Cargo.toml
    └── src
        └── lib.rs          <-- [OIDC Provider code]
```

<!--[bonsai access]: https://bonsai.xyz/apply-->
[cargo-risczero]: https://docs.rs/cargo-risczero
[crates]: https://github.com/risc0/risc0/blob/main/README.md#rust-binaries
[dev-docs]: https://dev.risczero.com
[dev-mode]: https://dev.risczero.com/api/generating-proofs/dev-mode
[docs.rs]: https://docs.rs/releases/search?query=risc0
[examples]: https://github.com/risc0/risc0/tree/main/examples
[risc0-build]: https://docs.rs/risc0-build
[risc0-repo]: https://www.github.com/risc0/risc0
[risc0-zkvm]: https://docs.rs/risc0-zkvm
[rust-toolchain]: rust-toolchain.toml
[rustup]: https://rustup.rs
[zkvm-overview]: https://dev.risczero.com/zkvm
