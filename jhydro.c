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
#include <math.h>

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
    (void) argv;
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
            janet_buffer_extra(buf, outlen);
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
    janet_buffer_extra(buf, len);
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
#ifdef JANET_ATEND_NAME
    JANET_ATEND_NAME
#endif
};

static Janet cfun_hash_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetByteView ctx = util_getnbytes(argv, 0, hydro_hash_CONTEXTBYTES);
    JanetByteView key = util_getnbytes(argv, 1, hydro_hash_KEYBYTES);
    hydro_hash_state *state = janet_abstract(&HashState, sizeof(hydro_hash_state));
    int result = hydro_hash_init(state, (const char *) ctx.bytes, key.bytes);
    if (result) {
        janet_panic("failed to create hash-state");
    }
    return janet_wrap_abstract(state);
}

static Janet cfun_hash_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    hydro_hash_state *state = janet_getabstract(argv, 0, &HashState);
    JanetByteView bytes = janet_getbytes(argv, 1);
    int result = hydro_hash_update(state, (const char *) bytes.bytes, bytes.len);
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
    int result = hydro_hash_hash(out, size, (const char *) msg.bytes, msg.len, (const char *) ctx.bytes, key.bytes);
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
        janet_buffer_extra(cipher, msg.len + hydro_secretbox_HEADERBYTES);
    } else {
        cipher = janet_buffer(msg.len + hydro_secretbox_HEADERBYTES);
    }
    int result = hydro_secretbox_encrypt(cipher->data + cipher->count,
            msg.bytes, msg.len, msg_id, (const char *) ctx.bytes, key.bytes);
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
        janet_buffer_extra(msg, ciphertext.len - hydro_secretbox_HEADERBYTES);
    } else {
        msg = janet_buffer(ciphertext.len - hydro_secretbox_HEADERBYTES);
    }
    int result = hydro_secretbox_decrypt(msg->data + msg->count,
            ciphertext.bytes, ciphertext.len, msg_id, (const char *) ctx.bytes, key.bytes);
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
    hydro_secretbox_probe_create(probe, c.bytes, c.len, (const char *) ctx.bytes, key.bytes);
    return janet_wrap_string(janet_string_end(probe));
}

static Janet cfun_secretbox_probe_verify(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 4);
    JanetByteView probe = util_getnbytes(argv, 0, hydro_secretbox_PROBEBYTES);
    JanetByteView c = janet_getbytes(argv, 1);
    JanetByteView ctx = util_getnbytes(argv, 2, hydro_secretbox_CONTEXTBYTES);
    JanetByteView key = util_getnbytes(argv, 3, hydro_secretbox_KEYBYTES);
    return janet_wrap_boolean(
            !hydro_secretbox_probe_verify(probe.bytes, c.bytes, c.len, (const char *) ctx.bytes, key.bytes));
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
    int result = hydro_kdf_derive_from_key(subkey, subkey_len, subkey_id, (const char *) ctx.bytes, key.bytes);
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
    int result = hydro_sign_create(csig, msg.bytes, msg.len, (const char *) ctx.bytes, sk.bytes);
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
                csig.bytes, msg.bytes, msg.len, (const char *) ctx.bytes, pk.bytes));
}

static const JanetAbstractType SignState = {
    "jhydro/sign-state",
#ifdef JANET_ATEND_NAME
    JANET_ATEND_NAME
#endif
};

static Janet cfun_sign_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetByteView ctx = util_getnbytes(argv, 0, hydro_sign_CONTEXTBYTES);
    hydro_sign_state *state = janet_abstract(&SignState, sizeof(hydro_sign_state));
    int result = hydro_sign_init(state, (const char *) ctx.bytes);
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

typedef struct {
    uint64_t opslimit;
    size_t memlimit;
    uint8_t threads;
} PwhashOpts;

static PwhashOpts util_pwhash_opts(int32_t argc, const Janet *argv, int32_t n) {
    PwhashOpts opts;
    opts.opslimit = 2000;
    opts.memlimit = 2000;
    opts.threads = 4;
    if (argc > n && !janet_checktype(argv[n], JANET_NIL)) {
        opts.opslimit = (uint64_t) util_getnat(argv, n);
    }
    if (argc > n + 1 && !janet_checktype(argv[n], JANET_NIL)) {
        opts.memlimit = (size_t) util_getnat(argv, n + 1);
    }
    if (argc > n + 2 && !janet_checktype(argv[n], JANET_NIL)) {
        int32_t threads_int = util_getnat(argv, n + 2);
        if (threads_int > 255) {
            janet_panicf("expected integer in range [0, 255] for threads, got %v", argv[6]);
        }
        opts.threads = (uint8_t) threads_int;
    }
    return opts;
}

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
    PwhashOpts opts = util_pwhash_opts(argc, argv, 4);
    uint8_t *str = janet_string_begin(h_len);
    int result = hydro_pwhash_deterministic(str, h_len, (const char *) passwd.bytes, passwd.len,
            (const char *) ctx.bytes, mk.bytes, opts.opslimit, opts.memlimit, opts.threads);
    if (result) {
        janet_panic("failed to hash password");
    }
    return janet_wrap_string(janet_string_end(str));
}

static Janet cfun_pwhash_create(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 5);
    JanetByteView passwd = janet_getbytes(argv, 0);
    JanetByteView mk = util_getnbytes(argv, 1, hydro_pwhash_MASTERKEYBYTES);
    PwhashOpts opts = util_pwhash_opts(argc, argv, 2);
    uint8_t *stored = janet_string_begin(hydro_pwhash_STOREDBYTES);
    int result = hydro_pwhash_create(stored, (const char *) passwd.bytes,
            passwd.len, mk.bytes, opts.opslimit, opts.memlimit, opts.threads);
    if (result) {
        janet_panic("failed hashing password");
    }
    return janet_wrap_string(janet_string_end(stored));
}

static Janet cfun_pwhash_verify(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 6);
    JanetByteView stored = util_getnbytes(argv, 0, hydro_pwhash_STOREDBYTES);
    JanetByteView passwd = janet_getbytes(argv, 1);
    JanetByteView mk = util_getnbytes(argv, 2, hydro_pwhash_MASTERKEYBYTES);
    PwhashOpts opts = util_pwhash_opts(argc, argv, 3);
    int result = hydro_pwhash_verify(stored.bytes, (const char *) passwd.bytes, passwd.len,
            mk.bytes, opts.opslimit, opts.memlimit, opts.threads);
    return janet_wrap_boolean(!result);
}

static Janet cfun_pwhash_derive_static_key(int32_t argc, Janet *argv) {
    janet_arity(argc, 5, 8);
    int32_t klen = util_getnat(argv, 0);
    JanetByteView stored = util_getnbytes(argv, 1, hydro_pwhash_STOREDBYTES);
    JanetByteView passwd = janet_getbytes(argv, 2);
    JanetByteView ctx = util_getnbytes(argv, 3, hydro_pwhash_CONTEXTBYTES);
    JanetByteView mk = util_getnbytes(argv, 4, hydro_pwhash_MASTERKEYBYTES);
    PwhashOpts opts = util_pwhash_opts(argc, argv, 5);
    uint8_t *static_key = janet_string_begin(klen);
    int result = hydro_pwhash_derive_static_key(static_key, klen, stored.bytes,
            (const char *) passwd.bytes, passwd.len,
            (const char *) ctx.bytes,
            mk.bytes,
            opts.opslimit, opts.memlimit, opts.threads);
    if (result) {
        janet_panic("failed to create static key");
    }
    return janet_wrap_string(janet_string_end(static_key));
}

static Janet cfun_pwhash_reencrypt(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    JanetByteView stored = util_getnbytes(argv, 0, hydro_pwhash_STOREDBYTES);
    JanetByteView mk = util_getnbytes(argv, 1, hydro_pwhash_MASTERKEYBYTES);
    JanetByteView newmk = util_getnbytes(argv, 2, hydro_pwhash_MASTERKEYBYTES);
    uint8_t *newstored = janet_string_begin(hydro_pwhash_STOREDBYTES);
    memcpy(newstored, stored.bytes, hydro_pwhash_STOREDBYTES);
    int result = hydro_pwhash_reencrypt(newstored, mk.bytes, newmk.bytes);
    if (result) {
        janet_panic("failed to reencrypt password hash");
    }
    return janet_wrap_string(janet_string_end(newstored));
}

static Janet cfun_pwhash_upgrade(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 5);
    JanetByteView stored = util_getnbytes(argv, 0, hydro_pwhash_STOREDBYTES);
    JanetByteView mk = util_getnbytes(argv, 1, hydro_pwhash_MASTERKEYBYTES);
    PwhashOpts opts = util_pwhash_opts(argc, argv, 2);
    uint8_t *newstored = janet_string_begin(hydro_pwhash_STOREDBYTES);
    memcpy(newstored, stored.bytes, hydro_pwhash_STOREDBYTES);
    int result = hydro_pwhash_upgrade(newstored, mk.bytes,
            opts.opslimit, opts.memlimit, opts.threads);
    if (result) {
        janet_panic("failed to upgrade password hash");
    }
    return janet_wrap_string(janet_string_end(newstored));
}

/* Utilities */

static Janet cfun_memzero(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetBuffer *buffer = janet_getbuffer(argv, 0);
    hydro_memzero(buffer->data, buffer->count);
    return janet_wrap_buffer(buffer);
}

static Janet cfun_increment(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetBuffer *buffer = janet_getbuffer(argv, 0);
    hydro_increment(buffer->data, buffer->count);
    return janet_wrap_buffer(buffer);
}

static Janet cfun_equal(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetByteView lhs = janet_getbytes(argv, 0);
    JanetByteView rhs = janet_getbytes(argv, 1);
    if (lhs.len != rhs.len) return janet_wrap_false();
    return janet_wrap_boolean(hydro_equal(lhs.bytes, rhs.bytes, lhs.len));
}

static Janet cfun_compare(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetByteView lhs = janet_getbytes(argv, 0);
    JanetByteView rhs = janet_getbytes(argv, 1);
    if (lhs.len < rhs.len) return janet_wrap_integer(-1);
    if (lhs.len > rhs.len) return janet_wrap_integer(1);
    return janet_wrap_integer(hydro_compare(lhs.bytes, rhs.bytes, lhs.len));
}

static Janet cfun_bin2hex(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    JanetByteView bin = janet_getbytes(argv, 0);
    JanetBuffer *hex = (argc == 2) ? janet_getbuffer(argv, 1) : janet_buffer(bin.len * 2 + 1);
    if (argc == 2) {
        janet_buffer_extra(hex, 2 * bin.len + 1);
    }
    hydro_bin2hex((char *)(hex->data + hex->count), bin.len * 2 + 1, bin.bytes, bin.len);
    hex->count += 2 * bin.len;
    return janet_wrap_buffer(hex);
}

static Janet cfun_hex2bin(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 3);
    JanetByteView hex = janet_getbytes(argv, 0);
    JanetBuffer *bin = (argc >= 2) ? janet_getbuffer(argv, 1) : janet_buffer(hex.len >> 1);
    const char *ignore = NULL;
    if (argc >= 3 && !janet_checktype(argv[2], JANET_NIL)) {
        ignore = janet_getcstring(argv, 2);
    }
    janet_buffer_extra(bin, (hex.len >> 1));
    int result = hydro_hex2bin(bin->data + bin->count,
            hex.len >> 1, (const char *) hex.bytes, hex.len,
            ignore, NULL);
    if (result < 0) {
        janet_panic("failed to convert hex to binary");
    }
    bin->count += result;
    return janet_wrap_buffer(bin);
}

static Janet cfun_pad(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetBuffer *buffer = janet_getbuffer(argv, 0);
    size_t pad = janet_getsize(argv, 1);
    janet_buffer_extra(buffer, pad + 2);
    int result = hydro_pad(buffer->data, buffer->count, pad, buffer->capacity);
    if (result < 0) {
        janet_panic("failed to pad bytes");
    }
    buffer->count = result;
    return janet_wrap_buffer(buffer);
}

static Janet cfun_unpad(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetBuffer *buffer = janet_getbuffer(argv, 0);
    size_t blocksize = janet_getsize(argv, 1);
    int result = hydro_unpad(buffer->data, buffer->count, blocksize);
    if (result < 0) {
        janet_panic("failed to unpad buffer");
    }
    buffer->count = result;
    return janet_wrap_buffer(buffer);
}

/* Key Exchange (KX) */

static Janet util_kx_sessionkeypair(hydro_kx_session_keypair *kp) {
    JanetKV *st = janet_struct_begin(2);
    Janet tx = janet_stringv(kp->tx, hydro_kx_SESSIONKEYBYTES);
    Janet rx = janet_stringv(kp->rx, hydro_kx_SESSIONKEYBYTES);
    janet_struct_put(st, janet_ckeywordv("tx"), tx);
    janet_struct_put(st, janet_ckeywordv("rx"), rx);
    return janet_wrap_struct(janet_struct_end(st));
}

static Janet cfun_kx_keygen(int32_t argc, Janet *argv) {
    (void) argv;
    janet_fixarity(argc, 0);
    hydro_kx_keypair kp;
    hydro_kx_keygen(&kp);
    JanetKV *st = janet_struct_begin(2);
    Janet pk = janet_stringv(kp.pk, hydro_kx_PUBLICKEYBYTES);
    Janet sk = janet_stringv(kp.sk, hydro_kx_SECRETKEYBYTES);
    janet_struct_put(st, janet_ckeywordv("public-key"), pk);
    janet_struct_put(st, janet_ckeywordv("secret-key"), sk);
    return janet_wrap_struct(janet_struct_end(st));
}

static Janet cfun_kx_n_1(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    JanetBuffer *packet = janet_getbuffer(argv, 0);
    JanetByteView psk = util_getnbytes(argv, 1, hydro_kx_PSKBYTES);
    JanetByteView peer_psk = util_getnbytes(argv, 2, hydro_kx_PUBLICKEYBYTES);
    hydro_kx_session_keypair kp;
    janet_buffer_extra(packet, hydro_kx_N_PACKET1BYTES);
    int result = hydro_kx_n_1(&kp, packet->data + packet->count, psk.bytes, peer_psk.bytes);
    if (result < 0) {
        janet_panic("failed to generate packet 1 to send to peer");
    }
    packet->count += hydro_kx_N_PACKET1BYTES;
    return util_kx_sessionkeypair(&kp);
}

static Janet cfun_kx_n_2(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 4);
    JanetByteView packet = util_getnbytes(argv, 0, hydro_kx_N_PACKET1BYTES);
    JanetByteView psk = util_getnbytes(argv, 1, hydro_kx_PSKBYTES);
    JanetByteView static_pk = util_getnbytes(argv, 2, hydro_kx_PUBLICKEYBYTES);
    JanetByteView static_sk = util_getnbytes(argv, 3, hydro_kx_SECRETKEYBYTES);
    hydro_kx_keypair static_kp;
    memcpy(static_kp.sk, static_sk.bytes, hydro_kx_SECRETKEYBYTES);
    memcpy(static_kp.pk, static_pk.bytes, hydro_kx_PUBLICKEYBYTES);
    hydro_kx_session_keypair kp;
    int result = hydro_kx_n_2(&kp, packet.bytes, psk.bytes, &static_kp);
    if (result < 0) {
        janet_panic("failed to generate packet 2 to send to peer");
    }
    return util_kx_sessionkeypair(&kp);
}

/* KK variant */

static const JanetAbstractType KxState = {
    "jhydro/kx-state",
#ifdef JANET_ATEND_NAME
    JANET_ATEND_NAME
#endif
};

static Janet cfun_kx_kk_1(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 4);
    JanetBuffer *packet1 = janet_getbuffer(argv, 0);
    JanetByteView static_pk = util_getnbytes(argv, 1, hydro_kx_PUBLICKEYBYTES);
    JanetByteView pk = util_getnbytes(argv, 2, hydro_kx_PUBLICKEYBYTES);
    JanetByteView sk = util_getnbytes(argv, 3, hydro_kx_SECRETKEYBYTES);
    hydro_kx_state *state = janet_abstract(&KxState, sizeof(hydro_kx_state));
    janet_buffer_extra(packet1, hydro_kx_KK_PACKET1BYTES);
    hydro_kx_keypair kp;
    memcpy(&kp.pk, pk.bytes, hydro_kx_PUBLICKEYBYTES);
    memcpy(&kp.sk, sk.bytes, hydro_kx_SECRETKEYBYTES);
    int result = hydro_kx_kk_1(state, packet1->data + packet1->count, static_pk.bytes, &kp);
    if (result < 0) {
        janet_panic("failed to generate packet 1 to send to peer");
    }
    packet1->count += hydro_kx_KK_PACKET1BYTES;
    return janet_wrap_abstract(state);
}

static Janet cfun_kx_kk_2(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 5);
    JanetBuffer *packet2 = janet_getbuffer(argv, 0);
    janet_buffer_extra(packet2, hydro_kx_KK_PACKET2BYTES);
    JanetByteView packet1 = util_getnbytes(argv, 1, hydro_kx_KK_PACKET1BYTES);
    JanetByteView static_pk = util_getnbytes(argv, 2, hydro_kx_PUBLICKEYBYTES);
    JanetByteView pk = util_getnbytes(argv, 3, hydro_kx_PUBLICKEYBYTES);
    JanetByteView sk = util_getnbytes(argv, 4, hydro_kx_SECRETKEYBYTES);
    hydro_kx_keypair kp;
    memcpy(&kp.pk, pk.bytes, hydro_kx_PUBLICKEYBYTES);
    memcpy(&kp.sk, sk.bytes, hydro_kx_SECRETKEYBYTES);
    hydro_kx_session_keypair skp;
    int result = hydro_kx_kk_2(&skp, packet2->data, packet1.bytes, static_pk.bytes, &kp);
    if (result < 0) {
        janet_panic("failed to generate session keypair");
    }
    packet2->count += hydro_kx_KK_PACKET2BYTES;
    return util_kx_sessionkeypair(&skp);
}

static Janet cfun_kx_kk_3(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 4);
    hydro_kx_state *state = janet_getabstract(argv, 0, &KxState);
    JanetByteView packet2 = util_getnbytes(argv, 1, hydro_kx_KK_PACKET2BYTES);
    JanetByteView pk = util_getnbytes(argv, 2, hydro_kx_PUBLICKEYBYTES);
    JanetByteView sk = util_getnbytes(argv, 3, hydro_kx_SECRETKEYBYTES);
    hydro_kx_session_keypair skp;
    hydro_kx_keypair kp;
    memcpy(&kp.pk, pk.bytes, hydro_kx_PUBLICKEYBYTES);
    memcpy(&kp.sk, sk.bytes, hydro_kx_SECRETKEYBYTES);
    int result = hydro_kx_kk_3(state, &skp, packet2.bytes, &kp);
    if (result < 0) {
        janet_panic("failed to generate session keypair");
    }
    return util_kx_sessionkeypair(&skp);
}

/* XX Variant */

static Janet cfun_kx_xx_1(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetBuffer *packet1 = janet_getbuffer(argv, 0);
    JanetByteView psk = util_getnbytes(argv, 1, hydro_kx_PSKBYTES);
    janet_buffer_extra(packet1, hydro_kx_XX_PACKET1BYTES);
    hydro_kx_state *state = janet_abstract(&KxState, sizeof(hydro_kx_state));
    int result = hydro_kx_xx_1(state, packet1->data + packet1->count, psk.bytes);
    if (result) {
        janet_panic("failed to generate packet 1 to send to peer");
    }
    packet1->count += hydro_kx_XX_PACKET1BYTES;
    return janet_wrap_abstract(state);
}

static Janet cfun_kx_xx_2(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 5);
    JanetBuffer *packet2 = janet_getbuffer(argv, 0);
    JanetByteView packet1 = util_getnbytes(argv, 1, hydro_kx_XX_PACKET1BYTES);
    JanetByteView psk = util_getnbytes(argv, 2, hydro_kx_PSKBYTES);
    JanetByteView pk = util_getnbytes(argv, 3, hydro_kx_PUBLICKEYBYTES);
    JanetByteView sk = util_getnbytes(argv, 4, hydro_kx_SECRETKEYBYTES);
    hydro_kx_keypair kp;
    memcpy(&kp.pk, pk.bytes, hydro_kx_PUBLICKEYBYTES);
    memcpy(&kp.sk, sk.bytes, hydro_kx_SECRETKEYBYTES);
    hydro_kx_state *state = janet_abstract(&KxState, sizeof(hydro_kx_state));
    janet_buffer_extra(packet2, hydro_kx_XX_PACKET2BYTES);
    int result = hydro_kx_xx_2(state, packet2->data + packet2->count, packet1.bytes, psk.bytes, &kp);
    if (result < 0) {
        janet_panic("failed to generate packet 2 to send to peer");
    }
    packet2->count += hydro_kx_XX_PACKET2BYTES;
    return janet_wrap_abstract(state);
}

static Janet cfun_kx_xx_3(int32_t argc, Janet *argv) {
    janet_arity(argc, 6, 7);
    hydro_kx_state *state = janet_getabstract(argv, 0, &KxState);
    JanetBuffer *packet3 = janet_getbuffer(argv, 1);
    JanetByteView packet2 = util_getnbytes(argv, 2, hydro_kx_XX_PACKET2BYTES);
    JanetByteView psk = util_getnbytes(argv, 3, hydro_kx_PSKBYTES);
    JanetByteView pk = util_getnbytes(argv, 4, hydro_kx_PUBLICKEYBYTES);
    JanetByteView sk = util_getnbytes(argv, 5, hydro_kx_SECRETKEYBYTES);
    hydro_kx_keypair kp;
    hydro_kx_session_keypair skp;
    memcpy(&kp.pk, pk.bytes, hydro_kx_PUBLICKEYBYTES);
    memcpy(&kp.sk, sk.bytes, hydro_kx_SECRETKEYBYTES);
    janet_buffer_extra(packet3, hydro_kx_XX_PACKET3BYTES);
    uint8_t *peer_pk = NULL;
    if (argc > 6) {
        JanetBuffer *buffer = janet_getbuffer(argv, 6);
        janet_buffer_extra(buffer, hydro_kx_PUBLICKEYBYTES);
        peer_pk = buffer->data + buffer->count;
        buffer->count += hydro_kx_PUBLICKEYBYTES;
    }
    int result = hydro_kx_xx_3(state, &skp, packet3->data + packet3->count, peer_pk, packet2.bytes, psk.bytes, &kp);
    if (result < 0) {
        janet_panic("failed to generate session keypair");
    }
    packet3->count += hydro_kx_XX_PACKET3BYTES;
    return util_kx_sessionkeypair(&skp);
}

static Janet cfun_kx_xx_4(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 4);
    hydro_kx_state *state = janet_getabstract(argv, 0, &KxState);
    JanetByteView packet3 = util_getnbytes(argv, 1, hydro_kx_XX_PACKET3BYTES);
    JanetByteView psk = util_getnbytes(argv, 2, hydro_kx_PSKBYTES);
    uint8_t *peer_pk = NULL;
    hydro_kx_session_keypair skp;
    if (argc > 3) {
        JanetBuffer *buffer = janet_getbuffer(argv, 3);
        janet_buffer_extra(buffer, hydro_kx_PUBLICKEYBYTES);
        peer_pk = buffer->data + buffer->count;
        buffer->count += hydro_kx_PUBLICKEYBYTES;
    }
    int result = hydro_kx_xx_4(state, &skp, peer_pk, packet3.bytes, psk.bytes);
    if (result) {
        janet_panic("failed to generate session keypair");
    }
    return util_kx_sessionkeypair(&skp);
}

/****************/
/* Module Entry */
/****************/

static const JanetReg cfuns[] = {

    /* Random */
    {"random/u32", cfun_random_u32, "(random/u32)\n\n"
        "Generate a psuedo random 32 bit unsigned integer"},
    {"random/uniform", cfun_random_uniform, "(random/uniform top)\n\n"
        "Generate a random 32 bit unsigned integer less than top."},
    {"random/buf", cfun_random_buf, "(random/buf buf &opt size)\n\n"
        "Fill a buffer with random bytes. If size is not provided, it will clear "
        "and fill the given buffer. If size is provided, will append size random "
        "bytes to the buffer. if you provide just the size argument,"
        "a new randomized buffer will be returned."},
    {"random/ratchet", cfun_random_ratchet, "(random/ratchet)\n\n"
        "Increment the internal state of the RNG."},
    {"random/reseed", cfun_random_reseed, "(random/reseed)\n\n"
        "Provide a new random seed for the internal RNG."},
    {"random/buf-deterministic", cfun_random_buf_deterministic,
        "(random/buf-deterministic buf len seed)\n\n"
            "Generate len random bytes and push them into a buffer buf. seed "
            "is a byte sequence of 32 bytes that initializes the state of the RNG. "
            "With same seed and len returns always the same buffer. Suitable for testing. "
            "Returns the modified buffer."},
    /* Hashing */
    {"hash/keygen", cfun_hash_keygen, "(hash/keygen &opt buf)\n\n"
        "Generate a key suitable for use in hashing. The key is a buffer of at "
        "least 32 bytes. If a buffer buf is provided, the first 32 bytes of buf "
        "will be set to a new random key. Returns a key buffer."},
    {"hash/new-state", cfun_hash_new, "(hash/new-state ctx key)\n\n"
        "Create a new hash-state. Takes a context ctx and a key and returns a new abstract type, "
        "jhydro/hash-state. Both ctx and key should be byte sequences, of lengths 8 and 32 "
        "respectively. Returns the new state."},
    {"hash/update", cfun_hash_update, "(hash/update state bytes)\n\n"
        "Add more bytes to the hash state. Returns the modified state"},
    {"hash/final", cfun_hash_final, "(hash/final state len)\n\n"
        "Get the final hash after digesting all of the input as a string. The resulting "
        "hash will be a string of length len."},
    {"hash/hash", cfun_hash_hash, "(hash/hash size input ctx &opt key)\n\n"
        "Hash some input bytes into an output string of length size. Optionally provide "
        "a key that can be used to generate different hashes on the same input."},
    /* Secret Box - symmetric encryption */
    {"secretbox/keygen", cfun_secretbox_keygen, "(secretbox/keygen)\n\n"
        "Generate a key suitable for secretbox. The returned key is a 32 byte buffer."},
    {"secretbox/encrypt", cfun_secretbox_encrypt,
        "(secretbox/encrypt msg msg-id ctx key &opt buf)\n\n"
        "Encrypt a message with a secretbox key and return the cipher text in a buffer. "
        "Also requires a message id, which is an integer, and a ctx, which is a non-secret "
        "byte-sequence. Lastly, requires a secret symmetric key for encryption. An optional "
        "buffer will prevent Janet from creating a new buffer, and instead append to and return "
        "the provided buffer."},
    {"secretbox/decrypt", cfun_secretbox_decrypt,
        "(secretbox/decrypt cipher-text msg-id ctx key &opt buf)\n\n"
        "Decrypt a cipher text that was produced with secretbox/encrypt. msg-id, "
        "ctx, and key must be the same as those used to encrypt the message. An optional "
        "buffer can be used to contain the plain text, otherwise a new buffer is created. "
        "Returns a buffer containing the plain text."},
    {"secretbox/probe-create", cfun_secretbox_probe_create,
        "(secretbox/probe-create cipher-text ctx key)\n\n"
        "Create a probe for some cipher text created by secretbox/encrypt. The "
        "resulting probe is a constant length string that can be used to verify if cipher text "
        "is valid before decrypting the entire text. Probes can help mitigate "
        "attack with large invalid ciphertexts. Returns a string."},
    {"secretbox/probe-verify", cfun_secretbox_probe_verify,
        "(secretbox/probe-verify probe cipher-text ctx key)\n\n"
        "Use a probe produced by secretbox/probe-create to check if some cipher text "
        "is genuine. If the cipher text is not forged or tampered with, returns true, otherwise "
        "false. Genuine cipher text can then be decrypted. Returns a boolean."},
    /* KDF */
    {"kdf/keygen", cfun_kdf_keygen, "(kdf/keygen &opt buf)\n\n"
        "Generate a key for use in KDFs. Returns the modified buf if provided, or "
        "a new random buffer."},
    {"kdf/derive-from-key", cfun_kdf_derive_from_key,
        "(kdf/derive-from-key sublen subid ctx key)\n\n"
        "Generate a subkey from a master key. Takes a subid, which is "
        "a positive integer that represents the key id, and ctx, which is "
        "an 8 byte string that is usually an application constant. Finally, the "
        "last parameter is the master key. Returns a string of length sublen."},
    /* Public Key Signatures */
    {"sign/keygen", cfun_sign_keygen, "(sign/keygen)\n\n"
        "Create a random key pair for public key signing. Returns a struct containing a "
        ":public-key and a :secret-key as strings."},
    {"sign/keygen-deterministic", cfun_sign_keygen_deterministic,
        "(sign/keygen-deterministic seed)\n\n"
        "Create a key pair from a seed. Seed should be a byte sequence of at least "
        "32 bytes; random/buf should work well. Returns a struct of two key value "
        "pairs, a :secret-key and a :public-key. Each key is a string."},
    {"sign/create", cfun_sign_create, "(sign/create msg ctx sk)\n\n"
        "Create a new sigature from a message, ctx, and secret key. The message "
        "can be any byte sequence, the context ctx should be a byte sequence of "
        "8 bytes, and the secret key sk should be secret key as generated from sign/keygen or "
        "sign/keygen-deterministic. Returns a signature, which is a 64 byte string."},
    {"sign/verify", cfun_sign_verify, "(sign/verify csig msg ctx pk)\n\n"
        "Check a signature to determine if a message is authentic. csig is the signature as "
        "generated by sign/create or sign/final-create, msg is the message that "
        "we are checking, ctx is the context string, and pk is the public key. Returns a boolean, "
        "true if the signature is valid, false otherwise."},
    {"sign/new-state", cfun_sign_new, "(sign/new-state ctx)\n\n"
        "Create a new state machine for generating a signature. A state machine allows "
        "processing a message in chunks to generate a signature. A string ctx of 8 bytes "
        "is also required, and can be a hard coded string. Returns a new jhydro/sign-state."},
    {"sign/update", cfun_sign_update, "(sign/update state msg)\n\n"
        "Process a message chunk for generating a signature. Returns the modified signature state."},
    {"sign/final-create", cfun_sign_final_create, "(sign/final-create state sk)\n\n"
        "Create a signature from the sign-state. Takes a jhydro/sign-state state and a secret key sk. "
        "Returns the signature and also modifies the state."},
    {"sign/final-verify", cfun_sign_final_verify, "(sign/final-verify state csig pk)\n\n"
        "Verify a signature with a public key. Given a sign-state state, signature csig, and "
        "public key pk, return true if csig is valid, otherwise false."},
    /* Password Hashing */
    {"pwhash/keygen", cfun_pwhash_keygen, "(pwhash/keygen &opt buf)\n\n"
        "Generate a master key for use in hashing passwords. The master key is used to "
        "encrypt all hashed passwords for an extra level of security. Returns a buffer with "
        "the new key."},
    {"pwhash/deterministic", cfun_pwhash_deterministic,
        "(pwhash/deterministic hlen passwd ctx master-key &opt opslimit memlimit threads)\n\n"
            "Hash a password to produce a high entropy key. "
            "The returned hashed password is a string of length hlen."},
    {"pwhash/create", cfun_pwhash_create,
        "(pwhash/create passwd masterkey &opt opslimit memlimit threads)\n\n"
            "Hash a password and get a blob that can be safely stored in a database. "
            "The returned result is a 128 byte string. Can take optional parameters to tune "
            "the difficulty of the hash."},
    {"pwhash/verify", cfun_pwhash_verify,
        "(pwhash/verify stored passwd master-key &opt opslimit memlimit threads)\n\n"
        "Check if a password matches a stored password hash. Hashing options must be the same as "
        "the ones used to created the stored hash."},
    {"pwhash/derive-static-key", cfun_pwhash_derive_static_key,
        "(pwhash/derive-static-key keylen stored passwd ctx master-key &opt opslimit memlimit threads)\n\n"
        "Derive a static key for used in cryptographic applications from a hashed password and other entropy "
        "(kept in stored). Returns a string with keylen bytes."},
    {"pwhash/reencrypt", cfun_pwhash_reencrypt,
        "(pwhash/reencrypt stored masterkey new-masterkey)\n\n"
        "Re-encrypt a hashed password under a new master key without needing the original password, only "
        "the previously hashed password and master key. Returns the new hashed password as a string."},
    {"pwhash/upgrade", cfun_pwhash_upgrade,
        "(pwhash/upgrade stored masterkey &opt opslimit memlimit threads)\n\n"
        "Change the encryption parameters of a key to make decrypting faster or slower. This can "
        "be used to scale difficulty of password hashing in the event of hardware advancements. Returns "
        "the new password hash as a string."},
    /* Utilities */
    {"util/memzero", cfun_memzero, "(util/memzero buffer)\n\n"
        "Clear memory in a buffer to 0, not changing the size of the buffer. Returns the "
        "modified buffer."},
    {"util/++", cfun_increment, "(util/++ buffer)\n\n"
        "Increment a buffer, treating it as a little endian large integer. If the increment results in an overflow, sets the "
        "buffer to all zero bytes. Returns the modified buffer."},
    {"util/=", cfun_equal, "(util/= lhs rhs)\n\n"
        "Compare the contents of two equal length buffers without early returns, which helps prevent side channel attacks. This "
        "is the function that should be used for comparing two buffers with cryptographic content. "
        "If the two buffers are of different lengths, returns early. Returns a boolen."},
    {"util/compare", cfun_compare, "(util/compare lhs rhs)\n\n"
        "Compare two buffers without early returns to help prevent side channel attacks. Returns an integer -1, 0, or 1."},
    {"util/bin2hex", cfun_bin2hex, "(util/bin2hex bin &opt hex)\n\n"
        "Convert binary data into hexidecimal. The hex representation of bin, the input buffer, is "
        "converted to a ascii hexidecimal and put in the buffer hex, or a new buffer if hex is not supplied. Returns "
        "hex or a new buffer."},
    {"util/hex2bin", cfun_hex2bin, "(util/hex2bin hex &opt bin ignore)\n\n"
        "Convert a hexidecimal string to binary data. Can provide an optional bin to write into instead of creating a new "
        "buffer, and also a string of characters to ignore while reading hex. Returns the buffer bin or a new buffer."},
    {"util/pad", cfun_pad, "(util/pad buffer blocksize)\n\n"
        "Pad a buffer according to the ISO/IEC 7816-4 algorithm. Returns the modified buffer."},
    {"util/unpad", cfun_unpad, "(util/unpad buffer blocksize)\n\n"
        "Unpad a buffer padded via util/pad. Returns the modifed buffer."},
    /* Key Exchange */
    {"kx/keygen", cfun_kx_keygen, "(kx/keygen)\n\n"
        "Generate a keypair for use in key exchanges. Contains both a public key and a secret key. "
        "Returns a struct with two entries: :secret-key and a :public-key."},
    {"kx/n1", cfun_kx_n_1, "(kx/n1 packet-buf psk peer-pk)\n\n"
        "Create a session key and generate a packet on the client as the first step in the N variant key exchange. "
        "Also take a pre-shared key, and the peer's public key. Returns a session key as a struct of two "
        "entries, :tx and :rx, which are the transmit and receive keys for communicating with the peer."},
    {"kx/n2", cfun_kx_n_2, "(kx/n2 packet1 psk pk sk)\n\n"
        "Create a session key as the second step in the N variant key exchange on the server. "
        "packet1 is what kx/n1 put into a buffer (packet-buf), psk is a pre-shared key, pk is the server's "
        "public key, and sk is the server's secret key. Returns a session keypair that is a mirror of what is on "
        "the client, but :tx and :rx are swapped."},
    {"kx/kk1", cfun_kx_kk_1, "(kx/kk1 packet-1 static-pk pk sk)\n\n"
        "Generate the first packet for the KK variant key exchange. Returns a jhydro/ks-state "
        "abstract which contains some useful state for the key exchange. static-pk is the peer's "
        "public key, and pk and sk are the client's public and secret keys. Modifies the buffer packet-1 "
        "by appending new data."},
    {"kx/kk2", cfun_kx_kk_2, "(kx/kk2 packet-2 packet-1 static-pk pk sk)\n\n"
        "Generate the second packet and a session keypair in the KK variant key exchange. packet-2 is "
        "a buffer to put the new packet in. packet-1 is the packet received from the peer. static-pk is the "
        "other peer's public key, and pk and sk are the local client's public and secret keys. Returns a session keypair, "
        "which is a struct of two entries, :rx and :tx."},
    {"kx/kk3", cfun_kx_kk_3, "(kx/kk3 state packet-2 pk sk)\n\n"
        "Generate a session key on the initiating peer in the KK variant key exchange. state is the "
        "jhydro/kx-state from step 1, packet-2 is the packet from step 2, and pk and sk are the local client's "
        "public and secret keys. Returns a session keypair, which is a struct of two entries, :rx and :tx."},
    {"kx/xx1", cfun_kx_xx_1, "(kx/xx1 packet-1 psk)\n\n"
        "First step in XX variant key exchange. Takes in a packet buffer and pre-shared key, and "
        "generates the first packet. Also returns a jhydro/kx-state for use in future steps."},
    {"kx/xx2", cfun_kx_xx_2, "(kx/xx2 packet-2 packet-1 psk pk sk)\n\n"
        "Second step in XX variant key exchange. Takes a buffer for writing packet number 2 too, "
        "packet 1, a pre-shared key, and the local public key and secret key. Writes the second packet "
        "to packet-2, and returns a jhydro/kx-state."},
    {"kx/xx3", cfun_kx_xx_3, "(kx/xx3 state packet-3 packet-2 psk pk sk &opt peer-pk)\n\n"
        "Third step in XX variant key exchange. Takes the state returned from kx/xx1, a buffer "
        "packet-3 to write the final packet into, the packet packet-2 send from the other peer, a "
        "pre-shared key psk, and the public and secret keys of the local machine. Optionally "
        "takes a buffer to write the remote peer's public key into, so you can reject connections if "
        "they do not match the expected public key. Returns a session keypair, which is a struct with two "
        "entries, :rx and :tx."},
    {"kx/xx4", cfun_kx_xx_4, "(kx/xx4 state packet-3 psk &opt peer-pk)\n\n"
        "Fourth and final step in the XX key exchange variant. Takes the state returned from kx/xx2, "
        "the packet received from kx/xx3, and a pre-shared key psk. "
        "Optionally takes a buffer peer-pk, which will have the remote peer's "
        "public key written appended to it. Returns a session keypair, which contains :tx and :rx entires."},
    {NULL, NULL, NULL}
};

JANET_MODULE_ENTRY(JanetTable *env) {
    hydro_init();
    janet_cfuns(env, "jhydro", cfuns);

    /* Constants */

    /* Random */
    janet_def(env, "random/seed-bytes", janet_wrap_integer(hydro_random_SEEDBYTES),
            "Number of bytes in a seed for the RNG.");

    /* Hashing */
    janet_def(env, "hash/bytes", janet_wrap_integer(hydro_hash_BYTES),
            "Number of bytes in a generic, simple hash.");
    janet_def(env, "hash/bytes-max", janet_wrap_integer(hydro_hash_BYTES_MAX),
            "Maximum number of bytes allowed when creating a keyed hash.");
    janet_def(env, "hash/bytes-min", janet_wrap_integer(hydro_hash_BYTES_MIN),
            "Minimum number of bytes allowed when creating a keyed hash.");
    janet_def(env, "hash/context-bytes", janet_wrap_integer(hydro_hash_CONTEXTBYTES),
            "Number of bytes required in context buffer for hashing.");
    janet_def(env, "hash/key-bytes", janet_wrap_integer(hydro_hash_KEYBYTES),
            "Number of bytes in a key required for hashing.");

    /* Secretbox */
    janet_def(env, "secretbox/context-bytes",
            janet_wrap_integer(hydro_secretbox_CONTEXTBYTES),
            "Number of bytes in a context for secretbox functions.");
    janet_def(env, "secretbox/header-bytes", janet_wrap_integer(hydro_secretbox_HEADERBYTES),
            "Number of bytes in the header of an encrypted message.");
    janet_def(env, "secretbox/key-bytes", janet_wrap_integer(hydro_secretbox_KEYBYTES),
            "Number of bytes in a secretbox key.");
    janet_def(env, "secretbox/probe-bytes", janet_wrap_integer(hydro_secretbox_PROBEBYTES),
            "Number of bytes in a secretbox probe.");

    /* KDF */
    janet_def(env, "kdf/context-bytes", janet_wrap_integer(hydro_kdf_CONTEXTBYTES),
            "Number of bytes in context argument to jhydro/kdf functions.");
    janet_def(env, "kdf/key-bytes", janet_wrap_integer(hydro_kdf_KEYBYTES),
            "Number of bytes in a kdf key.");
    janet_def(env, "kdf/bytes-max", janet_wrap_integer(hydro_kdf_BYTES_MAX),
            "Maximum number of bytes allowed in kdf generated key.");
    janet_def(env, "kdf/bytes-min", janet_wrap_integer(hydro_kdf_BYTES_MIN),
            "Minimum number of bytes allowed in kdf generated key.");

    /* Signing */
    janet_def(env, "sign/bytes", janet_wrap_integer(hydro_sign_BYTES),
            "Number of bytes in a signature.");
    janet_def(env, "sign/context-bytes", janet_wrap_integer(hydro_sign_CONTEXTBYTES),
            "Number of bytes needed for a signature context.");
    janet_def(env, "sign/public-key-bytes", janet_wrap_integer(hydro_sign_PUBLICKEYBYTES),
            "Number of bytes in a public key for making signatures.");
    janet_def(env, "sign/secret-key-bytes", janet_wrap_integer(hydro_sign_SECRETKEYBYTES),
            "Number of bytes in a secret key for making signatures.");
    janet_def(env, "sign/seed-bytes", janet_wrap_integer(hydro_sign_SEEDBYTES),
            "Number of bytes in a seed for generating a key.");

    /* KX */
    janet_def(env, "kx/session-key-bytes", janet_wrap_integer(hydro_kx_SESSIONKEYBYTES),
            "Number of bytes in a session key (tx or rx key). These keys are used to encrypt and "
            "decrypt messages between two peers.");
    janet_def(env, "kx/public-key-bytes", janet_wrap_integer(hydro_kx_PUBLICKEYBYTES),
            "Number of bytes in a public key intended for key exchange.");
    janet_def(env, "kx/secret-key-bytes", janet_wrap_integer(hydro_kx_SECRETKEYBYTES),
            "Number of bytes in a secret key intended for key exchange.");
    janet_def(env, "kx/psk-bytes", janet_wrap_integer(hydro_kx_PSKBYTES),
            "Number of bytes in a pre-shared key for key exchange.");
    janet_def(env, "kx/n-packet-1-bytes", janet_wrap_integer(hydro_kx_N_PACKET1BYTES),
            "Number of bytes in the first packet sent in the N variant key exchange.");
    janet_def(env, "kx/kk-packet-1-bytes", janet_wrap_integer(hydro_kx_KK_PACKET1BYTES),
            "Number of bytes in the first packet sent in the KK variant key exchange.");
    janet_def(env, "kx/kk-packet-2-bytes", janet_wrap_integer(hydro_kx_KK_PACKET2BYTES),
            "Number of bytes in the second packet sent in the KK variant key exchange.");
    janet_def(env, "kx/xx-packet-1-bytes", janet_wrap_integer(hydro_kx_XX_PACKET1BYTES),
            "Number of bytes in the first packet sent in the XX variant key exchange.");
    janet_def(env, "kx/xx-packet-2-bytes", janet_wrap_integer(hydro_kx_XX_PACKET2BYTES),
            "Number of bytes in the second packet sent in the XX variant key exchange.");
    janet_def(env, "kx/xx-packet-3-bytes", janet_wrap_integer(hydro_kx_XX_PACKET3BYTES),
            "Number of bytes in the third packet sent in the XX variant key exchange.");
}
