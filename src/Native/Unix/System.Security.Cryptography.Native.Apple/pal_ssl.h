// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include <Security/Security.h>

enum
{
    PAL_TlsHandshakeState_Unknown = 0,
    PAL_TlsHandshakeState_Complete = 1,
    PAL_TlsHandshakeState_WouldBlock = 2,
    PAL_TlsHandshakeState_ServerAuthCompleted = 3,
    PAL_TlsHandshakeState_ClientAuthCompleted = 4,
};
typedef int32_t PAL_TlsHandshakeState;

enum
{
    PAL_TlsIo_Unknown = 0,
    PAL_TlsIo_Success = 1,
    PAL_TlsIo_WouldBlock = 2,
    PAL_TlsIo_ClosedGracefully = 3,
};
typedef int32_t PAL_TlsIo;

enum
{
    PAL_SslProtocol_None = 0,
    PAL_SslProtocol_Ssl2 = 12,
    PAL_SslProtocol_Ssl3 = 48,
    PAL_SslProtocol_Tls10 = 192,
    PAL_SslProtocol_Tls11 = 768,
    PAL_SslProtocol_Tls12 = 3072,
};
typedef int32_t PAL_SslProtocol;
