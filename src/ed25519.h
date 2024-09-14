#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>

#include "sha512.h"

#if defined(_WIN32)
    #if defined(ED25519_BUILD_DLL)
        #define ED25519_DECLSPEC __declspec(dllexport)
    #elif defined(ED25519_DLL)
        #define ED25519_DECLSPEC __declspec(dllimport)
    #else
        #define ED25519_DECLSPEC
    #endif
#else
    #define ED25519_DECLSPEC
#endif

typedef struct verify_context_ {
  const unsigned char *signature;
  const unsigned char *public_key;
  sha512_context hash;
} verify_context;

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ED25519_NO_SEED
int ED25519_DECLSPEC ed25519_create_seed(unsigned char *seed);
#endif

void ED25519_DECLSPEC ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
void ED25519_DECLSPEC ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);
int ED25519_DECLSPEC ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);
void ED25519_DECLSPEC ed25519_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar);
void ED25519_DECLSPEC ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);

void ED25519_DECLSPEC ed25519_verify_init(verify_context *ctx);
void ED25519_DECLSPEC ed25519_verify_update(verify_context *ctx, const unsigned char *message, size_t message_len);
int ED25519_DECLSPEC ed25519_verify_final(verify_context *ctx);

#ifdef __cplusplus
}
#endif

#endif
