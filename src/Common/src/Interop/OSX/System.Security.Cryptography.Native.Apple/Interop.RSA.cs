// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_RsaGenerateKey")]
        internal static extern int RsaGenerateKey(
            int keySizeInBits,
            out SafeSecKeyRefHandle pPublicKey,
            out SafeSecKeyRefHandle pPrivateKey,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_RsaImportEphemeralKey")]
        internal static extern int RsaImportEphemeralKey(
            byte[] pkcs1Key,
            int cbPkcs1Key,
            bool isPrivateKey,
            out SafeSecKeyRefHandle key,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_RsaExportKey")]
        internal static extern int RsaExportKey(
            SafeSecKeyRefHandle key,
            int exportPrivate,
            out SafeCFDataHandle cfDataOut,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_RsaSign")]
        private static extern int RsaSign(
            SafeSecKeyRefHandle key,
            byte[] pbDataHash,
            int cbDataHash,
            PAL_HashAlgorithm algorithm,
            out SafeCFDataHandle pSignatureOut,
            out SafeCreateHandle pErrorOut);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_RsaVerify")]
        private static extern int RsaVerify(
            SafeSecKeyRefHandle key,
            byte[] pbDataHash,
            int cbDataHash,
            byte[] pbSignature,
            int cbSignature,
            PAL_HashAlgorithm algorithm,
            out SafeCreateHandle pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern ulong AppleCryptoNative_RsaGetKeySizeInBytes(SafeSecKeyRefHandle publicKey);

        internal static int RsaGetKeySizeInBits(SafeSecKeyRefHandle publicKey)
        {
            ulong keySizeInBytes = AppleCryptoNative_RsaGetKeySizeInBytes(publicKey);

            checked
            {
                return (int)(keySizeInBytes * 8);
            }
        }

        internal static byte[] RsaSign(SafeSecKeyRefHandle key, byte[] hash, PAL_HashAlgorithm hashAlgorithm)
        {
            SafeCFDataHandle signature;
            SafeCreateHandle error;
            int ret = RsaSign(key, hash, hash.Length, hashAlgorithm, out signature, out error);

            using (error)
            using (signature)
            {
                if (ret == 1)
                {
                    return CoreFoundation.CFGetData(signature);
                }

                if (ret == -2)
                {
                    Debug.Assert(!error.IsInvalid, "Native layer indicated error object was populated");
                    // TODO: Throw a CFErrorRef-based exception
                    throw new CryptographicException("A CFError was produced");
                }

                Debug.Fail("RsaVerify returned {ret}");
                throw new CryptographicException();
            }
        }

        internal static bool RsaVerify(
            SafeSecKeyRefHandle key,
            byte[] hash,
            byte[] signature,
            PAL_HashAlgorithm algorithm)
        {
            SafeCreateHandle error;
            int ret = RsaVerify(key, hash, hash.Length, signature, signature.Length, algorithm, out error);

            using (error)
            {
                if (ret == 1)
                {
                    return true;
                }

                if (ret == 0)
                {
                    return false;
                }

                if (ret == -2)
                {
                    Debug.Assert(!error.IsInvalid, "Native layer indicated error object was populated");
                    // TODO: Throw a CFErrorRef-based exception
                    throw new CryptographicException("A CFError was produced");
                }

                Debug.Fail("RsaVerify returned {ret}");
                throw new CryptographicException();
            }
        }
    }
}