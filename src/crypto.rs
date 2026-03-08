use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use std::time::Instant;
use subtle::ConstantTimeEq;
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
    derive_key_with_params(password, salt, 65_536, 3, 1)
}

pub fn derive_key_with_params(
    password: &str,
    salt: &[u8; 32],
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
) -> Zeroizing<[u8; 32]> {
    let params = Params::new(memory_kb, iterations, parallelism, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .unwrap();
    key
}

pub fn benchmark_argon2() -> (u32, u32, u32) {
    let salt = [7u8; 32];
    let password = "benchmark-password";
    let iterations = 3;
    let parallelism = 1;
    let mut memory_kb = 65_536;

    loop {
        let start = Instant::now();
        let _ = derive_key_with_params(password, &salt, memory_kb, iterations, parallelism);
        if start.elapsed().as_millis() >= 300 || memory_kb >= 1_048_576 {
            break;
        }
        memory_kb = (memory_kb * 2).min(1_048_576);
    }

    (memory_kb, iterations, parallelism)
}

pub fn encrypt(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .expect("encryption failed")
}

pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "decryption failed — wrong password or tampered data".to_string())
}

pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn constant_time_compare(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = "my-test-password";
        let plaintext = b"OPENAI_KEY=sk-test-1234";

        let salt = generate_salt();
        let nonce = generate_nonce();
        let key = derive_key(password, &salt);

        let ciphertext = encrypt(plaintext, &key, &nonce);
        let decrypted = decrypt(&ciphertext, &key, &nonce).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
        println!("✓ round-trip passed");
    }

    #[test]
    fn test_wrong_password_fails() {
        let salt = generate_salt();
        let nonce = generate_nonce();
        let key1 = derive_key("correct-password", &salt);
        let key2 = derive_key("wrong-password", &salt);

        let ciphertext = encrypt(b"secret", &key1, &nonce);
        let result = decrypt(&ciphertext, &key2, &nonce);

        assert!(result.is_err());
        println!("✓ wrong password correctly rejected");
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let salt = generate_salt();
        let nonce = generate_nonce();
        let key = derive_key("password", &salt);

        let mut ciphertext = encrypt(b"secret", &key, &nonce);
        ciphertext[0] ^= 0xFF; // flip a byte

        let result = decrypt(&ciphertext, &key, &nonce);
        assert!(result.is_err());
        println!("✓ tampered data correctly rejected");
    }

    #[test]
    fn test_generate_token_returns_64_char_hex() {
        let token = generate_token();

        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("abc", "abc"));
        assert!(!constant_time_compare("abc", "abd"));
    }

    #[test]
    fn test_benchmark_returns_values_within_bounds() {
        let (memory_kb, iterations, parallelism) = benchmark_argon2();
        assert!((65_536..=1_048_576).contains(&memory_kb));
        assert!(iterations >= 3);
        assert!(parallelism >= 1);
    }

    #[test]
    fn test_derive_key_with_params_roundtrip() {
        let salt = generate_salt();
        let nonce = generate_nonce();
        let key = derive_key_with_params("password", &salt, 65_536, 3, 1);
        let ciphertext = encrypt(b"secret", &key, &nonce);
        let decrypted = decrypt(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(decrypted, b"secret");
    }
}
