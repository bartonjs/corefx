// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_types.h"
#include "opensslshim.h"
/*
Generates the shared agreement secret from the two given keys.

No-op if pkey or peerkey is null.
*/
extern "C" byte* CryptoNative_EvpPkeyDeriveSecretAgreement(EVP_PKEY* pkey, EVP_PKEY* peerkey);
