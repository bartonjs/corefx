// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.Win32.SafeHandles;
using System;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_EvpPkeyCtxCreate")]
        internal static extern SafeEvpPkeyCtxHandle EvpPkeyCtxCreate(SafeEvpPKeyHandle pkey, SafeEvpPKeyHandle peerkey, out int secretLength);

        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_EvpPkeyDeriveSecretAgreement")]
        internal static extern void EvpPkeyDeriveSecretAgreement(byte[] secret, int secretLength, SafeEvpPkeyCtxHandle ctx);

        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_EvpPKeyCtxDestroy")]
        internal static extern void EvpPKeyCtxDestroy(IntPtr ctx);
    }
}
