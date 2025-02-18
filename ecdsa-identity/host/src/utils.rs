use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM for encryption
use dirs::data_dir;
use hex::encode;
use p384::ecdsa::signature::SignerMut;
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use p384::elliptic_curve::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use p384::elliptic_curve::rand_core::RngCore;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{Error, ErrorKind, Read, Write};
use std::path::Path;

// Derive a strong 256-bit encryption key from the password
fn derive_key(password: &str) -> [u8; 32] {
    let mut key_bytes = [0u8; 32];
    let salt = b"some_fixed_salt"; // Ideally, store a unique salt per user
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut key_bytes);

    key_bytes
}

pub fn handle_secp384r1_identity(
    account: &str,
    password: &str,
    message: &[u8],
) -> Result<(String, String), Error> {
    let config_path = data_dir()
        .expect("Failed to get data directory")
        .join("ecdsa_keys");

    // Ensure directory exists
    if !config_path.exists() {
        create_dir_all(&config_path).expect("Failed to create ECDSA keys directory");
    }

    let account_path = config_path.join(account);
    let mut private_key: SigningKey;

    if account_path.exists() {
        println!("Retrieving private key from config");
        private_key = decrypt_key(password, &account_path).expect("Failed to decrypt key");
    } else {
        println!("Generating new user private key");
        private_key = SigningKey::random(&mut OsRng);
        encrypt_key(password, &private_key, &account_path).expect("Failed to encrypt key");
    }

    let signature: Signature = private_key.sign(message);
    let public_key = VerifyingKey::from(&private_key);

    let binding = public_key.to_encoded_point(false);
    let pubkey_bytes = binding.as_bytes();

    Ok((encode(pubkey_bytes), encode(signature.to_der().as_bytes())))
}

// Encrypt & Save Data to File
fn encrypt_key(password: &str, private_key: &SigningKey, filepath: &Path) -> Result<(), Error> {
    let key = derive_key(password);
    let encryption_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(encryption_key);

    // Generate a random nonce (12 bytes for AES-GCM)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt data
    let plaintext = private_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .expect("Encryption failed");

    // Save (Nonce + Ciphertext) to file
    let mut file = File::create(filepath)?;
    file.write_all(&nonce_bytes)?;
    file.write_all(&ciphertext)?;
    Ok(())
}

// Decrypt Data from File
fn decrypt_key(password: &str, filepath: &Path) -> Result<SigningKey, Error> {
    let mut file = OpenOptions::new().read(true).open(filepath)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    // Extract nonce (first 12 bytes) and ciphertext
    if data.len() < 12 {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid encrypted data"));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);

    let key = derive_key(password);
    let encryption_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(encryption_key);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt the data
    let der_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Decryption failed"))?;

    // Convert decrypted bytes into SigningKey
    let private_key = SigningKey::from_pkcs8_der(&der_bytes)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid private key format"))?;

    Ok(private_key)
}
