use blake3::{Hash, Hasher};
use chacha20::XChaCha12;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use zeroize::Zeroize;

const CIPHER_CONTEXT: &'static str = "x123 BLAKE3 cipher";
const MACKEY_CONTEXT: &'static str = "x123 BLAKE3 mackey";

#[derive(Debug)]
pub enum Error {
    FailedMessageAuthentication,
}

/// Structure enabling authenticated encryption/decryption using XChaCha12 and BLAKE3.
pub struct Crypt {
    key: [u8; 32],
    mak: [u8; 32],
}

impl Drop for Crypt {
    fn drop(&mut self) {
        self.key.zeroize();
        self.mak.zeroize();
    }
}

impl Crypt {
    /// Initialize using the given key for all encryption/decryption.
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: blake3::derive_key(CIPHER_CONTEXT, key),
            mak: blake3::derive_key(MACKEY_CONTEXT, key),
        }
    }

    /// Encrypt the given buffer (in-place). Returns a tuple containing the nonce and MAC.
    pub fn encrypt(&self, buffer: &mut [u8], nonce: Option<&[u8]>) -> ([u8; 24], [u8; 32]) {
        let nonce = self.encrypt_buffer(buffer, nonce);

        (nonce, *self.calculate_mac(buffer, None).as_bytes())
    }

    /// Encrypt the given buffer (in-place). Returns a tuple containing the nonce and MAC (with the given data).
    pub fn encrypt_with_data(&self, buffer: &mut [u8], data: &[u8], nonce: Option<&[u8]>) -> ([u8; 24], [u8; 32]) {
        let nonce = self.encrypt_buffer(buffer, nonce);

        (nonce, *self.calculate_mac(buffer, Some(data)).as_bytes())
    }

    /// Encrypt the given buffer (in-place), returning the nonce.
    fn encrypt_buffer(&self, buffer: &mut [u8], nonce: Option<&[u8]>) -> [u8; 24] {
        // Determine the nonce to use.
        let nonce = get_nonce(nonce);

        // Encrypt using the saved key and earlier determined nonce.
        XChaCha12::new(&self.key.into(), &nonce.into())
            .apply_keystream(buffer);

        nonce
    }

    /// Decrypt the given buffer (in-place) using the given nonce, first validating the MAC.
    pub fn decrypt(&self, buffer: &mut [u8], nonce: &[u8; 24], mac: &[u8; 32]) -> Result<(), Error> {
        if !self.mac_valid(mac, buffer, None) {
            return Err(Error::FailedMessageAuthentication);
        }

        self.decrypt_buffer(buffer, nonce);

        Ok(())
    }

    /// Decrypt the given buffer (in-place) using the given nonce, first validating the MAC (with the given data).
    pub fn decrypt_with_data(&self, buffer: &mut [u8], data: &[u8], nonce: &[u8; 24], mac: &[u8; 32]) -> Result<(), Error> {
        if !self.mac_valid(mac, buffer, Some(data)) {
            return Err(Error::FailedMessageAuthentication);
        }

        self.decrypt_buffer(buffer, nonce);

        Ok(())
    }

    /// Decrypt the given buffer (in-place).
    fn decrypt_buffer(&self, buffer: &mut [u8], nonce: &[u8; 24]) {
        XChaCha12::new(&self.key.into(), nonce.into())
            .apply_keystream(buffer);
    }

    /// Calculate a MAC for the given buffer and optional data.
    fn calculate_mac(&self, buffer: &[u8], data: Option<&[u8]>) -> Hash {
        let mut hasher = Hasher::new_keyed(&self.mak);

        hasher.update(&buffer.len().to_be_bytes());
        hasher.update(buffer);
        
        if let Some(data) = data {
            hasher.update(&data.len().to_be_bytes());
            hasher.update(data);
        }

        hasher.finalize()
    }

    /// Determine if the given MAC matches the buffer and optional data.
    fn mac_valid(&self, mac: &[u8; 32], buffer: &[u8], data: Option<&[u8]>) -> bool {
        self.calculate_mac(buffer, data) == Hash::from_bytes(*mac)
    }
}

/// Hash the given data to generate a nonce, or use random bytes if no data was given.
fn get_nonce(data: Option<&[u8]>) -> [u8; 24] {
    let mut nonce = [0u8; 24];

    match data {
        Some(data) => {
            Hasher::new()
                .update(data)
                .finalize_xof()
                .fill(&mut nonce);
        },
        None => {
            getrandom::getrandom(&mut nonce)
                .expect("failed to generate 24 random bytes");
        }
    }

    nonce
}

/// A wrapper around `Crypt::new`.
pub fn new(key: &[u8]) -> Crypt {
    Crypt::new(key)
}