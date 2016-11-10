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
        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeyImportEphemeral(
            byte[] pbKeyBlob,
            int cbKeyBlob,
            int isPrivateKey,
            out SafeSecKeyRefHandle ppKeyOut,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_GenerateSignature(
            SafeSecKeyRefHandle privateKey,
            byte[] pbDataHash,
            int cbDataHash,
            out SafeCFDataHandle pSignatureOut,
            out SafeCFErrorHandle pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_GenerateSignatureWithHashAlgorithm(
            SafeSecKeyRefHandle privateKey,
            byte[] pbDataHash,
            int cbDataHash,
            PAL_HashAlgorithm hashAlgorithm,
            out SafeCFDataHandle pSignatureOut,
            out SafeCFErrorHandle pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_VerifySignature(
            SafeSecKeyRefHandle publicKey,
            byte[] pbDataHash,
            int cbDataHash,
            byte[] pbSignature,
            int cbSignature,
            out SafeCFErrorHandle pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_VerifySignatureWithHashAlgorithm(
            SafeSecKeyRefHandle publicKey,
            byte[] pbDataHash,
            int cbDataHash,
            byte[] pbSignature,
            int cbSignature,
            PAL_HashAlgorithm hashAlgorithm,
            out SafeCFErrorHandle pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern ulong AppleCryptoNative_SecKeyGetSimpleKeySizeInBytes(SafeSecKeyRefHandle publicKey);

        internal static int GetSimpleKeySizeInBits(SafeSecKeyRefHandle publicKey)
        {
            ulong keySizeInBytes = AppleCryptoNative_SecKeyGetSimpleKeySizeInBytes(publicKey);

            checked
            {
                return (int)(keySizeInBytes * 8);
            }
        }
        internal static SafeSecKeyRefHandle ImportEphemeralKey(byte[] keyBlob, bool hasPrivateKey)
        {
            Debug.Assert(keyBlob != null);

            SafeSecKeyRefHandle keyHandle;
            int osStatus;

            int ret = AppleCryptoNative_SecKeyImportEphemeral(
                keyBlob,
                keyBlob.Length,
                hasPrivateKey ? 1 : 0,
                out keyHandle,
                out osStatus);

            if (ret == 1 && !keyHandle.IsInvalid)
            {
                return keyHandle;
            }

            if (ret == 0)
            {
                throw CreateExceptionForCCError(osStatus, OSStatus);
            }

            Debug.Fail($"SecKeyImportEphemeral returned {ret}");
            throw new CryptographicException();
        }

        internal static byte[] GenerateSignature(SafeSecKeyRefHandle privateKey, byte[] dataHash)
        {
            Debug.Assert(privateKey != null, "privateKey != null");
            Debug.Assert(dataHash != null, "dataHash != null");

            SafeCFDataHandle signature;
            SafeCFErrorHandle error;

            int ret = AppleCryptoNative_GenerateSignature(
                privateKey,
                dataHash,
                dataHash.Length,
                out signature,
                out error);

            using (error)
            using (signature)
            {
                if (ret == 1)
                {
                    return CoreFoundation.CFGetData(signature);
                }

                if (ret == -2)
                {
                    throw CreateExceptionForCFError(error);
                }

                Debug.Fail("GenerateSignature returned {ret}");
                throw new CryptographicException();
            }
        }

        internal static byte[] GenerateSignature(
            SafeSecKeyRefHandle privateKey,
            byte[] dataHash,
            PAL_HashAlgorithm hashAlgorithm)
        {
            Debug.Assert(privateKey != null, "privateKey != null");
            Debug.Assert(dataHash != null, "dataHash != null");
            Debug.Assert(hashAlgorithm != PAL_HashAlgorithm.Unknown, "hashAlgorithm != PAL_HashAlgorithm.Unknown");

            SafeCFDataHandle signature;
            SafeCFErrorHandle error;

            int ret = AppleCryptoNative_GenerateSignatureWithHashAlgorithm(
                privateKey,
                dataHash,
                dataHash.Length,
                hashAlgorithm,
                out signature,
                out error);

            using (error)
            using (signature)
            {
                if (ret == 1)
                {
                    return CoreFoundation.CFGetData(signature);
                }

                if (ret == -2)
                {
                    throw CreateExceptionForCFError(error);
                }

                Debug.Fail("GenerateSignature returned {ret}");
                throw new CryptographicException();
            }
        }

        internal static bool VerifySignature(
            SafeSecKeyRefHandle publicKey,
            byte[] dataHash,
            byte[] signature)
        {
            Debug.Assert(publicKey != null, "publicKey != null");
            Debug.Assert(dataHash != null, "dataHash != null");
            Debug.Assert(signature != null, "signature != null");

            SafeCFErrorHandle error;

            int ret = AppleCryptoNative_VerifySignature(
                publicKey,
                dataHash,
                dataHash.Length,
                signature,
                signature.Length,
                out error);

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
                    throw CreateExceptionForCFError(error);
                }

                Debug.Fail("VerifySignature returned {ret}");
                throw new CryptographicException();
            }
        }

        internal static bool VerifySignature(
            SafeSecKeyRefHandle publicKey,
            byte[] dataHash,
            byte[] signature,
            PAL_HashAlgorithm hashAlgorithm)
        {
            Debug.Assert(publicKey != null, "publicKey != null");
            Debug.Assert(dataHash != null, "dataHash != null");
            Debug.Assert(signature != null, "signature != null");
            Debug.Assert(hashAlgorithm != PAL_HashAlgorithm.Unknown);

            SafeCFErrorHandle error;

            int ret = AppleCryptoNative_VerifySignatureWithHashAlgorithm(
                publicKey,
                dataHash,
                dataHash.Length,
                signature,
                signature.Length,
                hashAlgorithm,
                out error);

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
                    throw CreateExceptionForCFError(error);
                }

                Debug.Fail("VerifySignature returned {ret}");
                throw new CryptographicException();
            }
        }
    }
}

namespace System.Security.Cryptography.Apple
{
    internal sealed class SafeSecKeyRefHandle : SafeHandle
    {
        internal SafeSecKeyRefHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.CoreFoundation.CFRelease(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid => handle == IntPtr.Zero;
    }
}