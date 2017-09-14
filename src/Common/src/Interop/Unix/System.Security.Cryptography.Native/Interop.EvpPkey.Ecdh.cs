// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_EvpPkeyDeriveSecretAgreement")]
        private static extern void CryptoNative_EvpPkeyDeriveSecretAgreement(byte[] secret, int secretLength, IntPtr ctx);

        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_EvpPkeyNewCtx")]
        private static extern IntPtr CryptoNative_EvpPkeyNewCtx(SafeEvpPKeyHandle pkey, SafeEvpPKeyHandle peerkey, out int secretLength);

        internal static byte[] EvpPkeyDeriveSecretAgreement(SafeEvpPKeyHandle key, SafeEvpPKeyHandle peerkey)
        {
            int secretLength;
            IntPtr ctx = CryptoNative_EvpPkeyNewCtx(key, peerkey, out secretLength);
            byte[] secret = ArrayPool<Byte>.Shared.Rent(secretLength);
            unsafe
            {
                CryptoNative_EvpPkeyDeriveSecretAgreement(secret, secretLength, ctx);
            }
            return secret;
        }
    }
}
