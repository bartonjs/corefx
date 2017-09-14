// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_types.h"
#include "opensslshim.h"

extern "C" EVP_PKEY_CTX* CryptoNative_EvpPkeyNewCtx(EVP_PKEY* pkey, EVP_PKEY* peerkey, size_t *secretLength);

extern "C" void CryptoNative_EvpPkeyDeriveSecretAgreement(uint8_t *secret, size_t secretLength, EVP_PKEY_CTX *ctx);

extern "C" void CryptoNative_EvpPkeyCtxDestroy(EVP_PKEY_CTX* ctx);