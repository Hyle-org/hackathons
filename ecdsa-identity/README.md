# SECP384r1 Identity - RISC0 Example

This project demonstrates how to use **SECP384r1 (NIST P-384) cryptography** to create identity proofs on **Hylé**. It generates a secure key pair, encrypts the private key for local storage, and verifies identity using **zero-knowledge proofs (ZKPs)**.  

---

## **🔧 Prerequisites**

Before running the example, ensure you have:

- **Rust Installed**: [Install Rust](https://www.rust-lang.org/tools/install) (`rustup` and Cargo are required).
- **RISC Zero Installed**: [Install RISC Zero](https://dev.risczero.com/api/zkvm/install).
- **Hylé Devnet Running**: [Start a single-node devnet](https://docs.hyle.eu/developers/quickstart/devnet/).
  - Use **dev-mode** with `RISC0_DEV_MODE=1` for faster iterations:  

    ```sh
    export RISC0_DEV_MODE=1
    ```

---

## **🚀 Quickstart Guide**

### **1️⃣ Build and Register the Identity Contract**

To compile and deploy the identity contract on Hylé:

```sh
cargo run -- register-contract
```

✅ Expected output:

```
✅ Register contract tx sent. Tx hash: <tx hash>
```

---

### **2️⃣ Register an Account (Sign Up)**

To register an account, provide an **account name** and **password**:

```sh
cargo run -- register-identity alice my_secure_password
```

#### **🔍 What Happens?**

1. A **new SECP384r1 key pair is generated**.
2. The **private key is encrypted** with the provided password and stored in your device’s `datadir`.
3. The **public key is extracted** and used for verification.
4. The **private key signs** the message `"Hyle Registration"`.
5. The **signature and public key** are sent to Hylé for registration.

✅ Expected node logs:

```
INFO hyle::data_availability::node_state::verifiers: ✅ RISC0 proof verified.
```

---

### **3️⃣ Verify an Identity (Login)**

To verify an existing identity:

```sh
cargo run -- verify-identity alice my_secure_password
```

#### **🔍 What Happens?**

1. The **private key is decrypted** using the password.
2. The private key **signs a verification message**.
3. The **signature is sent to Hylé for verification**.
4. The system checks if the identity exists:
   - ✅ **If registered:** Proof verification succeeds.
   - ❌ **If no identity exists:** The request fails at the Hylé endpoint.

✅ Expected node logs (if verification is successful):

```
INFO hyle::data_availability::node_state::verifiers: ✅ RISC0 proof verified.
```

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
│       └── lib.rs         <-- [Contract code goes here, common to host & guest]
├── host
│   ├── Cargo.toml
│   └── src
│       └── main.rs        <-- [Host code goes here]
└── methods
    ├── Cargo.toml
    ├── build.rs
    ├── guest
    │   ├── Cargo.toml
    │   └── src
    │       └── main.rs    <-- [Guest code goes here]
    └── src
        └── lib.rs
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
