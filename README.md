# x123
(Experimental) Authenticated Encryption with XChaCha12 and BLAKE3.

Notes:
- **Though this library encrypts data, the implementation has _NOT_ been independently reviewed and thus should _NOT_ be considered secure!**
- Uses **XChaCha12** for the cipher.
- Uses **BLAKE3** for the KDF and MAC.
- The MAC is calculated _after_ encryption.
- Supports using a specific or random nonce.
- Supports encrypting with associated data.

References:
- [Wikipedia - Authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data)
- [Wikipedia - ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305#Description)