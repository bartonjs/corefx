// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_evp_pkey_ecdh.h"

//extern "C" uint8_t* CryptoNative_EvpPkeyDeriveSecretAgreement(EVP_PKEY* pkey, EVP_PKEY* peerkey, uint8_t *secret)
//{
//    //TODO: this needs some refactoring
//    EVP_PKEY_CTX *ctx;
//    uint8_t *secret;
//    size_t secretLength;
//
//    ///* Get the peer's public key, and provide the peer with our public key -
//    //* how this is done will be specific to your circumstances */
//    //peerkey = get_peerkey(pkey);
//
//    /* Create the context for the shared secret derivation */
//    if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL)))
//        return 0;
//
//    /* Initialise */
//    if (1 != EVP_PKEY_derive_init(ctx)) 
//        return 0;
//
//    /* Provide the peer public key */
//    if (1 != EVP_PKEY_derive_set_peer(ctx, peerkey)) 
//        return 0;
//
//    /* Determine buffer length for shared secret */
//    if (1 != EVP_PKEY_derive(ctx, NULL, &secretLength))
//        return 0;
//
//    /* Create the buffer */
//    if (NULL == (secret = OPENSSL_malloc(secretLength)))
//        return 0;
//
//    /* Derive the shared secret */
//    if (1 != (EVP_PKEY_derive(ctx, secret, &secretLength)))
//        return 0;
//
//    EVP_PKEY_CTX_free(ctx);
//
//    return secret;
//}

extern "C" EVP_PKEY_CTX* CryptoNative_EvpPkeyNewCtx(EVP_PKEY* pkey, EVP_PKEY* peerkey, size_t *secretLength)
{
    //TODO: this needs some refactoring
    EVP_PKEY_CTX *ctx;

    ///* Get the peer's public key, and provide the peer with our public key -
    //* how this is done will be specific to your circumstances */
    //peerkey = get_peerkey(pkey);

    /* Create the context for the shared secret derivation */
    if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL)))
        return 0;

    /* Initialise */
    if (1 != EVP_PKEY_derive_init(ctx))
        return 0;

    /* Provide the peer public key */
    if (1 != EVP_PKEY_derive_set_peer(ctx, peerkey))
        return 0;

    /* Determine buffer length for shared secret */
    if (1 != EVP_PKEY_derive(ctx, NULL, secretLength))
        return 0;

    return ctx;
}

extern "C" EVP_PKEY_CTX* CryptoNative_EvpPkeyDeriveSecretAgreement(uint8_t *secret, size_t *secretLength, EVP_PKEY_CTX *ctx)
{
    if (1 != (EVP_PKEY_derive(ctx, secret, secretLength)))
        return 0;

    EVP_PKEY_CTX_free(ctx);

    return secret;
}

