#include "ed25519.h"
#include "sha512.h"
#include "ge.h"
#include "sc.h"

static int consttime_equal(const unsigned char *x, const unsigned char *y) {
    unsigned char r = 0;

    r = x[0] ^ y[0];
    #define F(i) r |= x[i] ^ y[i]
    F(1);
    F(2);
    F(3);
    F(4);
    F(5);
    F(6);
    F(7);
    F(8);
    F(9);
    F(10);
    F(11);
    F(12);
    F(13);
    F(14);
    F(15);
    F(16);
    F(17);
    F(18);
    F(19);
    F(20);
    F(21);
    F(22);
    F(23);
    F(24);
    F(25);
    F(26);
    F(27);
    F(28);
    F(29);
    F(30);
    F(31);
    #undef F

    return !r;
}

int ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key) {
  verify_context ctx;
  ctx.signature = signature;
  ctx.public_key = public_key;
  ed25519_verify_init(&ctx);
  ed25519_verify_update(&ctx, message, message_len);
  return ed25519_verify_final(&ctx);
}

void ed25519_verify_init(verify_context *ctx) {
    sha512_init(&ctx->hash);
    sha512_update(&ctx->hash, ctx->signature, 32);
    sha512_update(&ctx->hash, ctx->public_key, 32);
}

void ed25519_verify_update(verify_context *ctx, const unsigned char *message, size_t message_len) {
  sha512_update(&ctx->hash, message, message_len);
}

int ed25519_verify_final(verify_context *ctx) {
    unsigned char h[64];
    unsigned char checker[32];
    ge_p3 A;
    ge_p2 R;

    if (ctx->signature[63] & 224) {
        return 0;
    }

    if (ge_frombytes_negate_vartime(&A, ctx->public_key) != 0) {
        return 0;
    }

    sha512_final(&ctx->hash, h);

    sc_reduce(h);
    ge_double_scalarmult_vartime(&R, h, &A, ctx->signature + 32);
    ge_tobytes(checker, &R);

    if (!consttime_equal(checker, ctx->signature)) {
        return 0;
    }

    return 1;
}
