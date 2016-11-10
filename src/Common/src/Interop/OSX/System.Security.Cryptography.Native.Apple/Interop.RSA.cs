// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
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

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_RsaEncryptOaep")]
        private static extern int RsaEncryptOaep(
            SafeSecKeyRefHandle publicKey,
            byte[] pbData,
            int cbData,
            PAL_HashAlgorithm mgfAlgorithm,
            out SafeCFDataHandle pEncryptedOut,
            out SafeCFErrorHandle pErrorOut);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_RsaEncryptPkcs")]
        private static extern int RsaEncryptPkcs(
            SafeSecKeyRefHandle publicKey,
            byte[] pbData,
            int cbData,
            out SafeCFDataHandle pEncryptedOut,
            out SafeCFErrorHandle pErrorOut);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_RsaDecryptOaep")]
        private static extern int RsaDecryptOaep(
            SafeSecKeyRefHandle publicKey,
            byte[] pbData,
            int cbData,
            PAL_HashAlgorithm mgfAlgorithm,
            out SafeCFDataHandle pEncryptedOut,
            out SafeCFErrorHandle pErrorOut);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_RsaDecryptPkcs")]
        private static extern int RsaDecryptPkcs(
            SafeSecKeyRefHandle publicKey,
            byte[] pbData,
            int cbData,
            out SafeCFDataHandle pEncryptedOut,
            out SafeCFErrorHandle pErrorOut);

        internal static byte[] RsaEncrypt(
            SafeSecKeyRefHandle publicKey,
            byte[] data,
            RSAEncryptionPadding padding)
        {
            int ret;
            SafeCFErrorHandle error;
            SafeCFDataHandle encrypted;

            if (padding == RSAEncryptionPadding.Pkcs1)
            {
                ret = RsaEncryptPkcs(publicKey, data, data.Length, out encrypted, out error);
            }
            else
            {
                ret = RsaEncryptOaep(
                    publicKey,
                    data,
                    data.Length,
                    PalAlgorithmFromAlgorithmName(padding.OaepHashAlgorithm),
                    out encrypted,
                    out error);
            }

            using (error)
            using (encrypted)
            {
                if (ret == 1)
                {
                    return CoreFoundation.CFGetData(encrypted);
                }

                if (ret == -2)
                {
                    throw CreateExceptionForCFError(error);
                }

                Debug.Fail("RsaVerify returned {ret}");
                throw new CryptographicException();
            }
        }

        internal static byte[] RsaDecrypt(
            SafeSecKeyRefHandle privateKey,
            byte[] data,
            RSAEncryptionPadding padding)
        {
            int ret;
            SafeCFErrorHandle error;
            SafeCFDataHandle decrypted;

            if (padding == RSAEncryptionPadding.Pkcs1)
            {
                ret = RsaDecryptPkcs(privateKey, data, data.Length, out decrypted, out error);
            }
            else
            {
                ret = RsaDecryptOaep(
                    privateKey,
                    data,
                    data.Length,
                    PalAlgorithmFromAlgorithmName(padding.OaepHashAlgorithm),
                    out decrypted,
                    out error);
            }

            using (error)
            using (decrypted)
            {
                if (ret == 1)
                {
                    return CoreFoundation.CFGetData(decrypted);
                }

                if (ret == -2)
                {
                    throw CreateExceptionForCFError(error);
                }

                Debug.Fail("RsaVerify returned {ret}");
                throw new CryptographicException();
            }
        }

        private static Interop.AppleCrypto.PAL_HashAlgorithm PalAlgorithmFromAlgorithmName(
                HashAlgorithmName hashAlgorithmName)
        {
            if (hashAlgorithmName == HashAlgorithmName.MD5)
            {
                return Interop.AppleCrypto.PAL_HashAlgorithm.Md5;
            }
            else if (hashAlgorithmName == HashAlgorithmName.SHA1)
            {
                return Interop.AppleCrypto.PAL_HashAlgorithm.Sha1;
            }
            else if (hashAlgorithmName == HashAlgorithmName.SHA256)
            {
                return Interop.AppleCrypto.PAL_HashAlgorithm.Sha256;
            }
            else if (hashAlgorithmName == HashAlgorithmName.SHA384)
            {
                return Interop.AppleCrypto.PAL_HashAlgorithm.Sha384;
            }
            else if (hashAlgorithmName == HashAlgorithmName.SHA512)
            {
                return Interop.AppleCrypto.PAL_HashAlgorithm.Sha512;
            }

            throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithmName.Name);
        }
    }
}