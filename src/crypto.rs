use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use argon2::{Argon2, Params, Algorithm, Version};
use rand::RngCore;
use zeroize::Zeroizing;

pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

pub fn derive_key(password: &str, salt: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let params = Params::new(65536, 3, 1, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(password.as_bytes(), salt, key.as_mut()).unwrap();
    key
}

pub fn encrypt(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.encrypt(Nonce::from_slice(nonce), plaintext).expect("encryption failed")
}

pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext).map_err(|_| "decryption failed — wrong password or tampered data".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = "my-test-password";
        let plaintext = b"OPENAI_KEY=sk-test-1234";

        let salt  = generate_salt();
        let nonce = generate_nonce();
        let key   = derive_key(password, &salt);

        let ciphertext = encrypt(plaintext, &key, &nonce);
        let decrypted  = decrypt(&ciphertext, &key, &nonce).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
        println!("✓ round-trip passed");
    }

    #[test]
    fn test_wrong_password_fails() {
        let salt  = generate_salt();
        let nonce = generate_nonce();
        let key1  = derive_key("correct-password", &salt);
        let key2  = derive_key("wrong-password",   &salt);

        let ciphertext = encrypt(b"secret", &key1, &nonce);
        let result     = decrypt(&ciphertext, &key2, &nonce);

        assert!(result.is_err());
        println!("✓ wrong password correctly rejected");
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let salt  = generate_salt();
        let nonce = generate_nonce();
        let key   = derive_key("password", &salt);

        let mut ciphertext = encrypt(b"secret", &key, &nonce);
        ciphertext[0] ^= 0xFF; // flip a byte

        let result = decrypt(&ciphertext, &key, &nonce);
        assert!(result.is_err());
        println!("✓ tampered data correctly rejected");
    }
}