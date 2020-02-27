
#include <stdint.h>
#include "memops.h"
#include "crypto_hash_sha512.h"

//below uses SHA2-512 from libsodium. would like to use SHA3-512 at some point but oh well
#define hash_state_t crypto_hash_sha512_state
#define HASH_INIT(p_state) crypto_hash_sha512_init(p_state)
#define HASH_UPDATE(p_state,buf,buflen) crypto_hash_sha512_update((p_state),(buf),(buflen))
#define HASH_FINAL(p_state,outbuf)  crypto_hash_sha512_final((p_state),(outbuf))
#define HASH_BLKSIZE crypto_hash_sha512_BYTES
#define HASH_OUTSIZE crypto_hash_sha512_BYTES

#define KDF_OUTSIZE HASH_OUTSIZE //the desired output size of the derived key. equal to hash output size.
#define KDF_ITER 4096 //this needs to go up alot lol
#define KDF_SALTSIZE 16 //gets padded, all good

//note: changes to SALTSIZE and OUTSIZE MUST be updated in cacti_sig.c or things WILL break

//#define KDF_USE_KMAC // <- use primarily with keccak, more efficient
#define KDF_USE_HMAC // <- use with length-extension vulnerable hashes (md-based like SHA2)

#ifdef _MSC_VER
#pragma region hmac
#endif

/*
function hmac is
    input:
        key:        Bytes     // Array of bytes
        message:    Bytes     // Array of bytes to be hashed
        hash:       Function  // The hash function to use (e.g. SHA-1)
        blockSize:  Integer   // The block size of the underlying hash function (e.g. 64 bytes for SHA-1)
        outputSize: Integer   // The output size of the underlying hash function (e.g. 20 bytes for SHA-1)

    // Keys longer than blockSize are shortened by hashing them
    if (length(key) > blockSize) then
        key <- hash(key) // Key becomes outputSize bytes long

    // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if (length(key) < blockSize) then
        key <- Pad(key, blockSize) // Pad key with zeros to make it blockSize bytes long

    o_key_pad <- key xor [0x5c * blockSize]   // Outer padded key
    i_key_pad <- key xor [0x36 * blockSize]   // Inner padded key

    return hash(o_key_pad || hash(i_key_pad || message)) // Where || is concatenation
*/

void hmac(uint8_t key[HASH_BLKSIZE], const uint8_t* msg, size_t msgsize, uint8_t out[HASH_OUTSIZE]) {
    hash_state_t state;
    uint8_t tmp[HASH_OUTSIZE];

    //get i_key_pad
    for (uint32_t i = 0; i < HASH_BLKSIZE; ++i) 
        key[i] ^= 0x36;

    //get inner hash
    HASH_INIT(&state);
    HASH_UPDATE(&state, key, HASH_BLKSIZE);
    HASH_UPDATE(&state, msg, msgsize);
    HASH_FINAL(&state, tmp); //not the true output
    
    //get o_key_pad
    for (uint32_t i = 0; i < HASH_BLKSIZE; ++i)
        key[i] ^= (0x36 ^ 0x5c);

    //get outer hash
    HASH_INIT(&state);
    HASH_UPDATE(&state, key, HASH_BLKSIZE);
    HASH_UPDATE(&state, tmp, HASH_OUTSIZE); //out stores the intermediate message hash RN
    HASH_FINAL(&state, out);

    //revert to original key
    for (uint32_t i = 0; i < HASH_BLKSIZE; ++i)
        key[i] ^= 0x5c;
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

//if keccac functionality is desired, https://gitweb.torproject.org/tor.git/tree/src/ext/keccak-tiny/keccak-tiny-unrolled.c should do it
#ifdef _MSC_VER
#pragma region kmac
#endif // _MSC_VER
//see NIST SP 800-185 (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)
//note: this is unimplemented lol

/*
K is a key bit string of any length, including zero.
X is the main input bit string. It may be of any length, including zero.
L is an integer representing the requested output length in bits. 
S is an optional customization bit string of any length, including zero. If no customization is desired, S is set to the empty string.

KMAC concatenates a padded version of the key K with the input X and an encoding of the requested output length L. 
The result is then passed to cSHAKE, along with the requested output length L, the 
name N ="KMAC" = 11010010 10110010 10000010 11000010, and the optional customization string S
*bits with low-bit leftmost

KMAC256(K, X, L, S): Validity Conditions: len(K) < 22040 and 0 <= L < 22040 and len(S) < 22040.
newX = bytepad(encode_string(K), 136) || X || right_encode(L). 
return cSHAKE256(newX, L, "KMAC", S).
Note that the numbers 168 and 136 are rates (in bytes) of the KECCAK[256] and KECCAK[512] sponge functions, respectively.
*/

void kmac(uint8_t* key, size_t klen, uint8_t* msg, size_t mlen, uint8_t out[HASH_OUTSIZE]) {
    /*
    left_encode(klen) = (klen >> 8) + 1 CONCAT klen (which I believe is little-endian?)
    encode_string(key) = left_encode(klen) CONCAT key[0:klen]

    */
}

#ifdef _MSC_VER
#pragma endregion
#endif // _MSC_VER

#ifdef _MSC_VER
#pragma region pbkdf2
#endif // _MSC_VER

/*
The PBKDF2 key derivation function has five input parameters:[8]

DK = PBKDF2(PRF, Password, Salt, c, dkLen)

where:

    PRF is a pseudorandom function of two parameters with output length hLen (e.g., a keyed HMAC)
    Password is the master password from which a derived key is generated
    Salt is a sequence of bits, known as a cryptographic salt
    c is the number of iterations desired
    dkLen is the desired bit-length of the derived key
    DK is the generated derived key

Each hLen-bit block Ti of derived key DK, is computed as follows (with + marking string concatenation):

DK = T1 + T2 + ... + Tdklen/hlen
Ti = F(Password, Salt, c, i)

The function F is the xor (^) of c iterations of chained PRFs. 
The first iteration of PRF uses Password as the PRF key and Salt concatenated with i encoded as a big-endian 32-bit integer as the input. 
(Note that i is a 1-based index.) 
Subsequent iterations of PRF use Password as the PRF key and the output of the previous PRF computation as the input:

F(Password, Salt, c, i) = U1 ^ U2 ^ ... ^ Uc

where:

U1 = PRF(Password, Salt + INT_32_BE(i))
U2 = PRF(Password, U1)
...
Uc = PRF(Password, Uc-1)
*/

/*
performs the pbkdf2 function on the pasword <pw> with length <pwlen>, using a salt <salt>.
writes the derived key into <out>
*/
void pbkdf2(const uint8_t * pw, size_t pwlen, const uint8_t salt[KDF_SALTSIZE], uint8_t out[KDF_OUTSIZE]) {
    //note: i is the ith iteration
    uint8_t tmp[HASH_OUTSIZE];
    //we don't do the i padding because we only generate with DK=Hlen, thus i never changes and no security is lost.

    memzero(out, HASH_OUTSIZE); //for the xoring later
#ifdef KDF_USE_HMAC
    uint8_t kbuf[HASH_BLKSIZE];
    if (pwlen > HASH_BLKSIZE) { //make the password suitable for use
        hash_state_t state;
        HASH_INIT(&state);
        HASH_UPDATE(&state, pw, pwlen);
        HASH_FINAL(&state, kbuf);
    }
    else {
        memcpy(kbuf, pw, pwlen);
        memzero(&(kbuf[pwlen]), HASH_BLKSIZE - pwlen);
    }
    hmac(kbuf, salt, KDF_SALTSIZE, tmp); //initial time, use salt as message
    for (size_t k = 0; k < HASH_OUTSIZE; ++k) 
        out[k] ^= tmp[k];
    for (size_t i = 1; i < KDF_ITER; ++i) { // 1-base is correct
        hmac(kbuf, tmp, HASH_OUTSIZE, tmp); //remaining times, use previous hashes as message
        for (size_t k = 0; k < HASH_OUTSIZE; ++k) 
            out[k] ^= tmp[k];
    }
#elif defined(KDF_USE_KMAC)
#error kmac is currently unimplemented
#else
#error must choose hmac or kmac
#endif // ! KDF_USE_KMAC && ! KDF_USE_HMAC    
}

#ifdef _MSC_VER
#pragma endregion
#endif