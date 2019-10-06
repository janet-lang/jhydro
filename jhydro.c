/*
* Copyright (c) 2019 Calvin Rose
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to
* deal in the Software without restriction, including without limitation the
* rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
* sell copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
* IN THE SOFTWARE.
*/

#include <janet.h>
#include <stdlib.h>
#include <hydrogen.h>

/*********/
/* Utils */
/*********/

/* Get an optional buffer for keygen functions, and ensure it has capacity for
 * len bytes */
static JanetBuffer *util_keygen_prep(int32_t argc, const Janet *argv, int len) {
    janet_arity(argc, 0, 1);
    JanetBuffer *buffer;
    if (argc == 0) {
        buffer = janet_buffer(len);
        buffer->count = len;
    } else {
        buffer = janet_getbuffer(argv, 0);
        janet_buffer_ensure(buffer, len, 1);
        if (buffer->count < len) {
            buffer->count = len;
        }
    }
    return buffer;
}

/* Get a byte view with at least nbytes bytes. Otherwise the same janet_getbytes. */
static JanetByteView util_getnbytes(const Janet *argv, int32_t n, int nbytes) {
    JanetByteView view = janet_getbytes(argv, n);
    if (view.len != nbytes) {
        janet_panicf("bad slot #%d, expected %d bytes, got %d", n, nbytes, view.len);
    }
    return view;
}

/* Get a positive, 32 bit integer */
static int32_t util_getnat(const Janet *argv, int32_t n) {
    int32_t x = janet_getinteger(argv, n);
    if (x < 0) {
        janet_panicf("bad slot #%d, expected non-negative integer, got %d", n, x);
    }
    return x;
}

/****************************/
/* Random Number Generation */
/****************************/

static Janet cfun_random_u32(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 0);
    uint32_t x = hydro_random_u32();
    return janet_wrap_number((double) x);
}

static Janet cfun_random_uniform(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    double d = janet_getnumber(argv, 0);
    if (d < 0 || d > UINT32_MAX || floor(d) != d) {
        janet_panicf("expected integer in range [0, 2^32), got %v", argv[0]);
    }
    uint32_t x = hydro_random_uniform((uint32_t) d);
    return janet_wrap_number((double) x);
}

static Janet cfun_random_buf(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    JanetBuffer *buf;
    size_t outlen;
    if (janet_checktype(argv[0], JANET_NUMBER)) {
        janet_fixarity(argc, 1);
        size_t outlen = janet_getsize(argv, 0);
        if (outlen > INT32_MAX) janet_panic("size too large");
        buf = janet_buffer(outlen);
        hydro_random_buf(buf->data, outlen);
        buf->count = outlen;
    } else {
        buf = janet_getbuffer(argv, 0);
        if (argc < 2) {
            outlen = buf->count;
            buf->count = 0;
        } else {
            outlen = janet_getsize(argv, 1);
            janet_buffer_ensure(buf, buf->count + outlen, 2);
        }
        if (outlen > INT32_MAX) janet_panic("size too large");
        hydro_random_buf(buf->data + buf->count, outlen);
        buf->count += outlen;
    }
    return janet_wrap_buffer(buf);
}

static Janet cfun_random_ratchet(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 0);
    (void) argv;
    hydro_random_ratchet();
    return janet_wrap_nil();
}

static Janet cfun_random_reseed(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 0);
    (void) argv;
    hydro_random_reseed();
    return janet_wrap_nil();
}

static Janet cfun_random_buf_deterministic(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    JanetBuffer *buf = janet_getbuffer(argv, 0);
    size_t len = janet_getsize(argv, 1);
    if (len > INT32_MAX) janet_panic("size too large");
    JanetByteView seed = util_getnbytes(argv, 2, hydro_random_SEEDBYTES);
    janet_buffer_ensure(buf, buf->count + len, 2);
    hydro_random_buf_deterministic(buf->data + buf->count, len, seed.bytes);
    buf->count += len;
    return janet_wrap_buffer(buf);
}

/***********/
/* Hashing */
/***********/

static Janet cfun_hash_keygen(int32_t argc, Janet *argv) {
    JanetBuffer *buffer = util_keygen_prep(argc, argv, hydro_hash_KEYBYTES);
    hydro_hash_keygen(buffer->data);
    return janet_wrap_buffer(buffer);
}

static const JanetAbstractType HashState = {
    "jhydro/hash-state",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static Janet cfun_hash_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetByteView ctx = util_getnbytes(argv, 0, hydro_hash_CONTEXTBYTES);
    JanetByteView key = util_getnbytes(argv, 1, hydro_hash_KEYBYTES);
    hydro_hash_state *state = janet_abstract(&HashState, sizeof(hydro_hash_state));
    int result = hydro_hash_init(state, ctx.bytes, key.bytes);
    if (result) {
        janet_panic("failed to create hash-state");
    }
    return janet_wrap_abstract(state);
}

static Janet cfun_hash_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    hydro_hash_state *state = janet_getabstract(argv, 0, &HashState);
    JanetByteView bytes = janet_getbytes(argv, 1);
    int result = hydro_hash_update(state, bytes.bytes, bytes.len);
    if (result) {
        janet_panic("failed to update hash-state");
    }
    return argv[0];
}

static Janet cfun_hash_final(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    hydro_hash_state *state = janet_getabstract(argv, 0, &HashState);
    int32_t outlen = janet_getinteger(argv, 1);
    if (outlen < 1) {
        janet_panicf("outlen must be a positive integer, got %v", argv[1]);
    }
    uint8_t *out = janet_string_begin(outlen);
    int result = hydro_hash_final(state, out, outlen);
    if (result) {
        janet_panic("failed to generate hash");
    }
    return janet_wrap_string(janet_string_end(out));
}

static Janet cfun_hash_hash(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 4);
    int32_t size = util_getnat(argv, 0);
    if (size < hydro_hash_BYTES_MIN || size > hydro_hash_BYTES_MAX)
        janet_panicf("hash size must be in range [%d, %d], got %v",
                hydro_hash_BYTES_MIN, hydro_hash_BYTES_MAX,
                argv[0]);
    JanetByteView msg = janet_getbytes(argv, 1);
    JanetByteView ctx = util_getnbytes(argv, 2, hydro_hash_CONTEXTBYTES);
    JanetByteView key;
    key.bytes = NULL;
    key.len = 0;
    if (argc >= 4 && !janet_checktype(argv[4], JANET_NIL)) {
        key = util_getnbytes(argv, 3, hydro_hash_KEYBYTES);
    }
    uint8_t *out = janet_string_begin(size);
    int result = hydro_hash_hash(out, size, msg.bytes, msg.len, ctx.bytes, key.bytes);
    if (result) {
        janet_panic("failed to hash message");
    }
    return janet_wrap_string(janet_string_end(out));
}

/**************/
/* Secret Box */
/**************/

static Janet cfun_secretbox_keygen(int32_t argc, Janet *argv) {
    JanetBuffer *buffer = util_keygen_prep(argc, argv, hydro_secretbox_KEYBYTES);
    hydro_secretbox_keygen(buffer->data);
    return janet_wrap_buffer(buffer);
}

static Janet cfun_secretbox_encrypt(int32_t argc, Janet *argv) {
    janet_arity(argc, 4, 5);
    JanetByteView msg = janet_getbytes(argv, 0);
    uint64_t msg_id = (uint64_t) janet_getinteger64(argv, 1);
    JanetByteView ctx = util_getnbytes(argv, 2, hydro_secretbox_CONTEXTBYTES);
    JanetByteView key = util_getnbytes(argv, 3, hydro_secretbox_KEYBYTES);
    JanetBuffer *cipher;
    if (argc == 5) {
        cipher = janet_getbuffer(argv, 4);
        janet_buffer_ensure(cipher,
                cipher->count + msg.len + hydro_secretbox_HEADERBYTES, 2);
    } else {
        cipher = janet_buffer(msg.len + hydro_secretbox_HEADERBYTES);
    }
    int result = hydro_secretbox_encrypt(cipher->data + cipher->count,
            msg.bytes, msg.len, msg_id, ctx.bytes, key.bytes);
    if (result) {
        janet_panic("encryption failed");
    }
    cipher->count += msg.len + hydro_secretbox_HEADERBYTES;
    return janet_wrap_buffer(cipher);
}

static Janet cfun_secretbox_decrypt(int32_t argc, Janet *argv) {
    janet_arity(argc, 4, 5);
    JanetByteView ciphertext = janet_getbytes(argv, 0);
    uint64_t msg_id = (uint64_t) janet_getinteger64(argv, 1);
    JanetByteView ctx = util_getnbytes(argv, 2, hydro_secretbox_CONTEXTBYTES);
    JanetByteView key = util_getnbytes(argv, 3, hydro_secretbox_KEYBYTES);
    JanetBuffer *msg;
    if (argc == 5) {
        msg = janet_getbuffer(argv, 4);
        janet_buffer_ensure(msg,
                msg->count + ciphertext.len - hydro_secretbox_HEADERBYTES, 2);
    } else {
        msg = janet_buffer(ciphertext.len - hydro_secretbox_HEADERBYTES);
    }
    int result = hydro_secretbox_decrypt(msg->data + msg->count,
            ciphertext.bytes, ciphertext.len, msg_id, ctx.bytes, key.bytes);
    if (result) {
        janet_panic("decryption failed");
    }
    msg->count += ciphertext.len - hydro_secretbox_HEADERBYTES;
    return janet_wrap_buffer(msg);
}

static Janet cfun_secretbox_probe_create(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    JanetByteView c = janet_getbytes(argv, 0);
    JanetByteView ctx = util_getnbytes(argv, 1, hydro_secretbox_CONTEXTBYTES);
    JanetByteView key = util_getnbytes(argv, 2, hydro_secretbox_KEYBYTES);
    uint8_t *probe = janet_string_begin(hydro_secretbox_PROBEBYTES);
    hydro_secretbox_probe_create(probe, c.bytes, c.len, ctx.bytes, key.bytes);
    return janet_wrap_string(janet_string_end(probe));
}

static Janet cfun_secretbox_probe_verify(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 4);
    JanetByteView probe = util_getnbytes(argv, 0, hydro_secretbox_PROBEBYTES);
    JanetByteView c = janet_getbytes(argv, 1);
    JanetByteView ctx = util_getnbytes(argv, 2, hydro_secretbox_CONTEXTBYTES);
    JanetByteView key = util_getnbytes(argv, 2, hydro_secretbox_KEYBYTES);
    return janet_wrap_boolean(
            !hydro_secretbox_probe_verify(probe.bytes, c.bytes, c.len, ctx.bytes, key.bytes));
}

/*******/
/* KDF */
/*******/

static Janet cfun_kdf_keygen(int32_t argc, Janet *argv) {
    JanetBuffer *buffer = util_keygen_prep(argc, argv, hydro_kdf_KEYBYTES);
    hydro_kdf_keygen(buffer->data);
    return janet_wrap_buffer(buffer);
}

static Janet cfun_kdf_derive_from_key(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 4);
    int32_t subkey_len = janet_getinteger(argv, 0);
    if (subkey_len < hydro_kdf_BYTES_MIN)
        janet_panicf("subkey length must be at least %d, got %d",
            hydro_kdf_BYTES_MIN, subkey_len);
    if (subkey_len > hydro_kdf_BYTES_MAX)
        janet_panicf("subkey length must be at most %d, got %d",
            hydro_kdf_BYTES_MAX, subkey_len);
    uint64_t subkey_id = (uint64_t) janet_getinteger64(argv, 1);
    JanetByteView ctx = util_getnbytes(argv, 2, hydro_kdf_CONTEXTBYTES);
    JanetByteView key = util_getnbytes(argv, 3, hydro_kdf_KEYBYTES);
    uint8_t *subkey = janet_string_begin(subkey_len);
    int result = hydro_kdf_derive_from_key(subkey, subkey_len, subkey_id, ctx.bytes, key.bytes);
    if (result) {
        janet_panic("failed to derive key");
    }
    return janet_wrap_string(janet_string_end(subkey));
}

/*************************/
/* Public Key Signatures */
/*************************/

static Janet util_make_keypair(hydro_sign_keypair *kp) {
    Janet pk = janet_stringv(kp->pk, hydro_sign_PUBLICKEYBYTES);
    Janet sk = janet_stringv(kp->sk, hydro_sign_SECRETKEYBYTES);
    JanetKV *st = janet_struct_begin(2);
    janet_struct_put(st, janet_ckeywordv("public-key"), pk);
    janet_struct_put(st, janet_ckeywordv("secret-key"), sk);
    return janet_wrap_struct(janet_struct_end(st));
}

static Janet cfun_sign_keygen(int32_t argc, Janet *argv) {
    hydro_sign_keypair kp;
    (void) argv;
    janet_fixarity(argc, 0);
    hydro_sign_keygen(&kp);
    return util_make_keypair(&kp);
}

static Janet cfun_sign_keygen_deterministic(int32_t argc, Janet *argv) {
    hydro_sign_keypair kp;
    janet_fixarity(argc, 1);
    JanetByteView seed = util_getnbytes(argv, 0, hydro_sign_SEEDBYTES);
    hydro_sign_keygen_deterministic(&kp, seed.bytes);
    return util_make_keypair(&kp);
}

static Janet cfun_sign_create(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    JanetByteView msg = janet_getbytes(argv, 0);
    JanetByteView ctx = util_getnbytes(argv, 1, hydro_sign_CONTEXTBYTES);
    JanetByteView sk = util_getnbytes(argv, 2, hydro_sign_SECRETKEYBYTES);
    uint8_t *csig = janet_string_begin(hydro_sign_BYTES);
    int result = hydro_sign_create(csig, msg.bytes, msg.len, ctx.bytes, sk.bytes);
    if (result) {
        janet_panic("failed to create signature");
    }
    return janet_wrap_string(janet_string_end(csig));
}

static Janet cfun_sign_verify(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 4);
    JanetByteView csig = util_getnbytes(argv, 0, hydro_sign_BYTES);
    JanetByteView msg = janet_getbytes(argv, 1);
    JanetByteView ctx = util_getnbytes(argv, 2, hydro_sign_CONTEXTBYTES);
    JanetByteView pk = util_getnbytes(argv, 3, hydro_sign_PUBLICKEYBYTES);
    return janet_wrap_boolean(!hydro_sign_verify(
                csig.bytes, msg.bytes, msg.len, ctx.bytes, pk.bytes));
}

static const JanetAbstractType SignState = {
    "jhydro/sign-state", NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static Janet cfun_sign_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetByteView ctx = util_getnbytes(argv, 0, hydro_sign_CONTEXTBYTES);
    hydro_sign_state *state = janet_abstract(&SignState, sizeof(hydro_sign_state));
    int result = hydro_sign_init(state, ctx.bytes);
    if (result) {
        janet_panic("failed to create signature state");
    }
    return janet_wrap_abstract(state);
}

static Janet cfun_sign_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    hydro_sign_state *state = janet_getabstract(argv, 0, &SignState);
    JanetByteView msg = janet_getbytes(argv, 1);
    int result = hydro_sign_update(state, msg.bytes, msg.len);
    if (result) {
        janet_panic("failed to update signature state");
    }
    return argv[0];
}

static Janet cfun_sign_final_create(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    hydro_sign_state *state = janet_getabstract(argv, 0, &SignState);
    JanetByteView sk = util_getnbytes(argv, 1, hydro_sign_SECRETKEYBYTES);
    uint8_t *csig = janet_string_begin(hydro_sign_BYTES);
    int result = hydro_sign_final_create(state, csig, sk.bytes);
    if (result) {
        janet_panic("failed to create signature");
    }
    return janet_wrap_string(janet_string_end(csig));
}

static Janet cfun_sign_final_verify(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    hydro_sign_state *state = janet_getabstract(argv, 0, &SignState);
    JanetByteView csig = util_getnbytes(argv, 1, hydro_sign_BYTES);
    JanetByteView pk = util_getnbytes(argv, 2, hydro_sign_PUBLICKEYBYTES);
    int result = hydro_sign_final_verify(state, csig.bytes, pk.bytes);
    return janet_wrap_boolean(!result);
}

/*******************/
/* Password Hashing */
/*******************/

static Janet cfun_pwhash_keygen(int32_t argc, Janet *argv) {
    JanetBuffer *buffer = util_keygen_prep(argc, argv, hydro_pwhash_MASTERKEYBYTES);
    hydro_pwhash_keygen(buffer->data);
    return janet_wrap_buffer(buffer);
}

static Janet cfun_pwhash_deterministic(int32_t argc, Janet *argv) {
    janet_arity(argc, 4, 7);
    int32_t h_len = util_getnat(argv, 0);
    JanetByteView passwd = janet_getbytes(argv, 1);
    JanetByteView ctx = util_getnbytes(argv, 2, hydro_pwhash_CONTEXTBYTES);
    JanetByteView mk = util_getnbytes(argv, 3, hydro_pwhash_MASTERKEYBYTES);
    uint64_t opslimit = 2000;
    size_t memlimit = 2000;
    uint8_t threads = 4;
    if (argc >= 5) {
        opslimit = (uint64_t) util_getnat(argv, 4);
    }
    if (argc >= 6) {
        memlimit = (size_t) util_getnat(argv, 5);
    }
    if (argc >= 7) {
        int32_t threads_int = util_getnat(argv, 6);
        if (threads_int > 255) {
            janet_panicf("expected integer in range [0, 255] for threads, got %v", argv[6]);
        }
        threads = (uint8_t) threads_int;
    }
    uint8_t *str = janet_string_begin(h_len);
    int result = hydro_pwhash_deterministic(str, h_len, passwd.bytes, passwd.len,
            ctx.bytes, mk.bytes, opslimit, memlimit, threads);
    if (result) {
        janet_panic("failed to hash password");
    }
    return janet_wrap_string(janet_string_end(str));
}

static Janet cfun_pwhash_create(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 5);
    JanetByteView passwd = janet_getbytes(argv, 0);
    JanetByteView mk = util_getnbytes(argv, 1, hydro_pwhash_MASTERKEYBYTES);
    uint64_t opslimit = 2000;
    size_t memlimit = 2000;
    uint8_t threads = 4;
    if (argc >= 3) {
        opslimit = (uint64_t) util_getnat(argv, 2);
    }
    if (argc >= 4) {
        memlimit = (size_t) util_getnat(argv, 3);
    }
    if (argc >= 5) {
        int32_t threads_int = util_getnat(argv, 4);
        if (threads_int > 255) {
            janet_panicf("expected integer in range [0, 255] for threads, got %v", argv[6]);
        }
        threads = (uint8_t) threads_int;
    }
    uint8_t *stored = janet_string_begin(hydro_pwhash_STOREDBYTES);
    int result = hydro_pwhash_create(stored, passwd.bytes,
            passwd.len, mk.bytes, opslimit, memlimit, threads);
    if (result) {
        janet_panic("failed hashing password");
    }
    return janet_wrap_string(janet_string_end(stored));
}

/*
int hydro_pwhash_verify(const uint8_t stored[hydro_pwhash_STOREDBYTES], const char *passwd,
                        size_t passwd_len, const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES],
                        uint64_t opslimit_max, size_t memlimit_max, uint8_t threads_max);

int hydro_pwhash_derive_static_key(uint8_t *static_key, size_t static_key_len,
                                   const uint8_t stored[hydro_pwhash_STOREDBYTES],
                                   const char *passwd, size_t passwd_len,
                                   const char    ctx[hydro_pwhash_CONTEXTBYTES],
                                   const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES],
                                   uint64_t opslimit_max, size_t memlimit_max, uint8_t threads_max);

int hydro_pwhash_reencrypt(uint8_t       stored[hydro_pwhash_STOREDBYTES],
                           const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES],
                           const uint8_t new_master_key[hydro_pwhash_MASTERKEYBYTES]);

int hydro_pwhash_upgrade(uint8_t       stored[hydro_pwhash_STOREDBYTES],
                         const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES], uint64_t opslimit,
                         size_t memlimit, uint8_t threads);
 */


/****************/
/* Module Entry */
/****************/

static const JanetReg cfuns[] = {

    /* Random */
    {"random/u32", cfun_random_u32, "(jhydro/random/u32)\n\n"
        "Generate a psuedo random 32 bit unsigned integer"},
    {"random/uniform", cfun_random_uniform, "(jhydro/random/uniform top)\n\n"
        "Generate a random 32 bit unsigned integer less than top."},
    {"random/buf", cfun_random_buf, "(jhydro/random/buf buf &opt size)\n\n"
        "Fill a buffer with random bytes. If size is not provided, will clear "
        "and fill the given buffer. If size is provided, will append size random "
        "bytes to the buffer. Alternatively, you can provide just the size argument, and "
        "a new randomized buffer will be returned."},
    {"random/ratchet", cfun_random_ratchet, "(jhydro/random/ratchet)\n\n"
        "Increment the internal state of the RNG."},
    {"random/reseed", cfun_random_reseed, "(jhydro/random/reseed)\n\n"
        "Provide a new random seed for the internal RNG."},
    {"random/buf-deterministic", cfun_random_buf_deterministic,
        "(jhydro/random/buf-deterministic buf len seed)\n\n"
            "Generate len random bytes and push them into a buffer buf. seed "
            "is a byte sequence of at least 32 bytes that initializes the state of the RNG. "
            "Returns the modified buffer."},
    /* Hashing */
    {"hash/keygen", cfun_hash_keygen, "(jhydro/hash/keygen &opt buf)\n\n"
        "Generate a key suitable for use in hashing. The key is a buffer of at "
        "least 32 bytes. If a buffer buf is provided, the first 32 bytes of buf "
        "will be set to a new random key. Returns a key buffer."},
    {"hash/new-state", cfun_hash_new, "(jhydro/hash/new-state ctx key)\n\n"
        "Create a new hash-state. Takes a context ctx and a key and returns a new abstract type, "
        "jhydro/hash-state. Both ctx and key should be byte sequences, of at least lengths 8 and 32 "
        "respectively. Returns the new state."},
    {"hash/update", cfun_hash_update, "(jhydro/hash/update state bytes)\n\n"
        "Add more bytes to the hash state. Returns the modified state"},
    {"hash/final", cfun_hash_final, "(jhydro/hash/final state len)\n\n"
        "Get the final hash after digesting all of the input as a string. The resulting "
        "hash will be a string of length len."},
    {"hash/hash", cfun_hash_hash, "(jhydro/hash/hash size input ctx &opt key)\n\n"
        "Hash some input bytes into an output string of length size. Optionally provide "
        "a key that can be used to generate different hashes on the same input."},
    /* Secret Box - symmetric encryption */
    {"secretbox/keygen", cfun_secretbox_keygen, "(jyhdro/secretbox/keygen)\n\n"
        "Generate a key suitable for secretbox. The returned key is a 32 byte buffer."},
    {"secretbox/encrypt", cfun_secretbox_encrypt,
        "(jhydro/secretbox/encrypt msg msg-id ctx key &opt buf)\n\n"
        "Encrypt a message with a secretbox key and return the cipher text in a buffer. "
        "Also requires a message id, which is an integer, and a ctx, which is a non-secret "
        "byte-sequence. Lastly, requires a secret symmetric key for encryption. An optional "
        "buffer will prevent Janet from creating a new buffer, and instead append to and return "
        "the provided buffer."},
    {"secretbox/decrypt", cfun_secretbox_decrypt,
        "(jhydro/secretbox/decrypt cipher-text msg-id ctx key &opt buf)\n\n"
        "Decrypt a cipher text that was produced with jhydro/secretbox/encrypt. msg-id, "
        "ctx, and key must be the same as those used to encrypt the message. An optional "
        "buffer can be used to contain the plain text, otherwise a new buffer is created. "
        "Returns a buffer containing the plain text."},
    {"secretbox/probe-create", cfun_secretbox_probe_create,
        "(jhydro/secretbox/probe-create cipher-text ctx key)\n\n"
        "Create a probe for some cipher text created by jhydro/secretbox/encrypt. The "
        "resulting probe is a constant length string that can be used to verify if cipher text "
        "is valid before decrypting the entire text. Returns a string."},
    {"secretbox/probe-verify", cfun_secretbox_probe_verify,
        "(jhydro/secretbox/probe-verify probe cipher-text ctx key)\n\n"
        "Use a probe produced by jhydro/secretbox/probe-create to check if some cipher text "
        "is genuine. If the cipher text is not forged or tampered with, returns true, otherwise "
        "false. Genuine cipher text can then be decrypted. Returns a boolean."},
    /* KDF */
    {"kdf/keygen", cfun_kdf_keygen, "(jhydro/kdf/keygen &opt buf)\n\n"
        "Generate a key for use in KDFs. Returns the modified buf if provided, or "
        "a new random buffer."},
    {"kdf/derive-from-key", cfun_kdf_derive_from_key,
        "(jhydro/kdf/derive-from-key sublen subid ctx key)\n\n"
        "Generate a subkey from a master key. Takes a subid, which is "
        "a positive integer that represents the key id, and ctx, which is "
        "an 8 byte string that is usually an application constant. Finally, the "
        "last parameter is the master key. Returns a string of length sublen."},
    /* Public Key Signatures */
    {"sign/keygen", cfun_sign_keygen, "(jhydro/sign/keygen)\n\n"
        "Create a random key pair for public key signing. Returns a struct containing a "
        ":public-key and a :secret-key as strings."},
    {"sign/keygen-deterministic", cfun_sign_keygen_deterministic,
        "(jhydro/sign/keygen-deterministic seed)\n\n"
        "Create a key pair from a seed. Seed should be a byte sequence of at least "
        "32 bytes; jhydro/random/buf should work well. Returns a struct of two key value "
        "pairs, a :secret-key and a :public-key. Each key is a string."},
    {"sign/create", cfun_sign_create, "(jhydro/sign/create msg ctx sk)\n\n"
        "Create a new sigature from a message, ctx, and secret key. The message "
        "can be any byte sequence, the context ctx should be a byte sequence of at least "
        "8 bytes, and the secret key sk should be secret key as generated from jhydro/sign/keygen or "
        "jhydro/sign/keygen-deterministic. Returns a signature, which is a 64 byte string."},
    {"sign/verify", cfun_sign_verify, "(jhydro/sign/verify csig msg ctx pk)\n\n"
        "Check a signature to determine if a message is authentic. csig is the signature as "
        "generated by jhydro/sign/create or jhydro/sign/final-create, msg is the message that "
        "we are checking, ctx is the context string, and pk is the public key. Returns a boolean, "
        "true if the signature is valid, false otherwise."},
    {"sign/new-state", cfun_sign_new, "(jhydro/sign/new-state ctx)\n\n"
        "Create a new state machine for generating a signature. A state machine allows "
        "processing a message in chunks to generate a signature. A string ctx of at least 8 bytes "
        "is also required, and can be a hrad coded string. Returns a new jhydro/sign-state."},
    {"sign/update", cfun_sign_update, "(jhydro/sign/update state msg)\n\n"
        "Process a message chunk for generating a signature. Returns the modified signature state."},
    {"sign/final-create", cfun_sign_final_create, "(jhydro/sign/final-create state sk)\n\n"
        "Create a signature from the sign-state. Takes a jhydro/sign-state state and a secret key sk. "
        "Returns the signature and also modifies the state."},
    {"sign/final-verify", cfun_sign_final_verify, "(jhydro/sign/final-verify state csig pk)\n\n"
        "Verify a signature with a public key. Given a sign-state state, signature csig, and "
        "public key pk, return true if csig is valid, otherwise false."},
    /* Password Hashing */
    {"pwhash/keygen", cfun_pwhash_keygen, "(jhydro/pwhash/keygen &opt buf)\n\n"
        "Generate a master key for use in hashing passwords. The master key is used to "
        "encrypt all hashed passwords for an extra level of security. Returns a buffer with "
        "the new key."},
    {"pwhash/deterministic", cfun_pwhash_deterministic,
        "(jhydro/pwhash/deterministic hlen passwd ctx masterkey &opt opslimit memlimit threads)\n\n"
            "Hash a password to produce a high entropy key. "
            "The returned hashed password is a string of length hlen."},
    {"pwhash/create", cfun_pwhash_create,
        "(jhydro/pwhash/create passwd masterkey &opt opslimit memlimit threads)\n\n"
            "Hash a password and get a blob that can be safely stored in a database. "
            "The returned result is a 128 byte string. Can take optional parameters to tune "
            "the difficulty of the hash."},
    {NULL, NULL, NULL}
};

JANET_MODULE_ENTRY(JanetTable *env) {
    hydro_init();
    janet_cfuns(env, "jhydro", cfuns);

    /* Constants */

    /* Random */
    janet_def(env, "random/SEEDBYTES", janet_wrap_integer(hydro_random_SEEDBYTES),
            "Number of bytes in a seed for the RNG.");

    /* Hashing */
    janet_def(env, "hash/BYTES", janet_wrap_integer(hydro_hash_BYTES),
            "Number of bytes in a generic, simple hash.");
    janet_def(env, "hash/BYTES-MAX", janet_wrap_integer(hydro_hash_BYTES_MAX),
            "Maximum number of bytes allowed when creating a keyed hash.");
    janet_def(env, "hash/BYTES-MIN", janet_wrap_integer(hydro_hash_BYTES_MIN),
            "Minimum number of bytes allowed when creating a keyed hash.");
    janet_def(env, "hash/CONTEXTBYTES", janet_wrap_integer(hydro_hash_CONTEXTBYTES),
            "Number of bytes required in context buffer for hashing.");
    janet_def(env, "hash/KEYBYTES", janet_wrap_integer(hydro_hash_KEYBYTES),
            "Number of bytes in a key required for hashing.");

    /* Secretbox */
    janet_def(env, "secretbox/CONTEXTBYTES",
            janet_wrap_integer(hydro_secretbox_CONTEXTBYTES),
            "Number of bytes in a context for secretbox functions.");
    janet_def(env, "secretbox/HEADERBYTES", janet_wrap_integer(hydro_secretbox_HEADERBYTES),
            "Number of bytes in the header of an encrypted message.");
    janet_def(env, "secretbox/KEYBYTES", janet_wrap_integer(hydro_secretbox_KEYBYTES),
            "Number of bytes in a secretbox key.");
    janet_def(env, "secretbox/PROBEBYTES", janet_wrap_integer(hydro_secretbox_PROBEBYTES),
            "Number of bytes in a secretbox probe.");

    /* KDF */
    janet_def(env, "kdf/CONTEXTBYTES", janet_wrap_integer(hydro_kdf_CONTEXTBYTES),
            "Number of bytes in context argument to jhydro/kdf functions.");
    janet_def(env, "kdf/KEYBYTES", janet_wrap_integer(hydro_kdf_KEYBYTES),
            "Number of bytes in a kdf key.");
    janet_def(env, "kdf/BYTES_MAX", janet_wrap_integer(hydro_kdf_BYTES_MAX),
            "Maximum number of bytes allowed in kdf generated key.");
    janet_def(env, "kdf/BYTES_MIN", janet_wrap_integer(hydro_kdf_BYTES_MIN),
            "Minimum number of bytes allowed in kdf generated key.");

    /* Signing */
    janet_def(env, "sign/BYTES", janet_wrap_integer(hydro_sign_BYTES),
            "Number of bytes in a signature.");
    janet_def(env, "sign/CONTEXTBYTES", janet_wrap_integer(hydro_sign_CONTEXTBYTES),
            "Number of bytes needed for a signature context.");
    janet_def(env, "sign/PUBLICKEYBYTES", janet_wrap_integer(hydro_sign_PUBLICKEYBYTES),
            "Number of bytes in a public key for making signatures.");
    janet_def(env, "sign/SECRETKEYBYTES", janet_wrap_integer(hydro_sign_SECRETKEYBYTES),
            "Number of bytes in a secret key for making signatures.");
    janet_def(env, "sign/SEEDBYTES", janet_wrap_integer(hydro_sign_SEEDBYTES),
            "Number of bytes in a seed for generating a key.");

}
