// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography
{
    public static partial class Pkcs8
    {
        public enum EncryptionAlgorithm
        {
            Unknown,
            Aes128Cbc,
            Aes192Cbc,
            Aes256Cbc,
        }
    }

    internal static class KeyFormatHelper
    {
        internal delegate void KeyReader<TRet, TParsed>(in TParsed key, in AlgorithmIdentifierAsn algId, out TRet ret);

        internal static void ReadSubjectPublicKeyInfo<TRet, TParsed>(
            string[] validOids,
            ReadOnlySpan<byte> source,
            KeyReader<TRet, TParsed> keyReader,
            out int bytesRead,
            out TRet ret)
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(source.Length);
            source.CopyTo(buf);
            Memory<byte> rwTmp = buf.AsMemory(0, source.Length);
            ReadOnlyMemory<byte> tmp = rwTmp;

            try
            {
                ReadSubjectPublicKeyInfo(validOids, tmp, keyReader, out bytesRead, out ret);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(rwTmp.Span);
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        internal static void ReadSubjectPublicKeyInfo<TRet, TParsed>(
            string[] validOids,
            ReadOnlyMemory<byte> source,
            KeyReader<TRet, TParsed> keyReader,
            out int bytesRead,
            out TRet ret)
        {
            // X.509 SubjectPublicKeyInfo is described as DER.
            SubjectPublicKeyInfo spki =
                AsnSerializer.Deserialize<SubjectPublicKeyInfo>(source, AsnEncodingRules.DER, out int read);

            if (Array.IndexOf(validOids, spki.Algorithm.Algorithm) < 0)
            {
                // TODO: Better message?
                throw new CryptographicException(SR.Cryptography_NotValidPublicOrPrivateKey);
            }

            TParsed parsed;

            if (typeof(TParsed) == typeof(ReadOnlyMemory<byte>))
            {
                ReadOnlyMemory<byte> tmp = spki.SubjectPublicKey;
                parsed = Unsafe.As<ReadOnlyMemory<byte>, TParsed>(ref tmp);
            }
            else
            {
                parsed = AsnSerializer.Deserialize<TParsed>(
                    spki.SubjectPublicKey,
                    AsnEncodingRules.DER);
            }

            keyReader(parsed, spki.Algorithm, out ret);
            bytesRead = read;
        }

        internal static void ReadPkcs8<TRet, TParsed>(
            string[] validOids,
            ReadOnlySpan<byte> source,
            KeyReader<TRet, TParsed> keyReader,
            out int bytesRead,
            out TRet ret)
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(source.Length);
            source.CopyTo(buf);
            Memory<byte> rwTmp = buf.AsMemory(0, source.Length);
            ReadOnlyMemory<byte> tmp = rwTmp;

            try
            {
                ReadPkcs8(validOids, tmp, keyReader, out bytesRead, out ret);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(rwTmp.Span);
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        internal static void ReadPkcs8<TRet, TParsed>(
            string[] validOids,
            ReadOnlyMemory<byte> source,
            KeyReader<TRet, TParsed> keyReader,
            out int bytesRead,
            out TRet ret)
        {
            PrivateKeyInfo privateKeyInfo =
                AsnSerializer.Deserialize<PrivateKeyInfo>(source, AsnEncodingRules.BER, out int read);

            if (Array.IndexOf(validOids, privateKeyInfo.PrivateKeyAlgorithm.Algorithm) < 0)
            {
                // TODO: Better message?
                throw new CryptographicException(SR.Cryptography_NotValidPublicOrPrivateKey);
            }

            // Fails if there are unconsumed bytes.
            TParsed parsed = AsnSerializer.Deserialize<TParsed>(
                privateKeyInfo.PrivateKey,
                AsnEncodingRules.BER);

            keyReader(parsed, privateKeyInfo.PrivateKeyAlgorithm, out ret);
            bytesRead = read;
        }

        internal static unsafe void ReadEncryptedPkcs8<TRet, TParsed>(
            string[] validOids,
            ReadOnlySpan<byte> source,
            ReadOnlySpan<char> password,
            KeyReader<TRet, TParsed> keyReader,
            out int bytesRead,
            out TRet ret)
        {
            System.Text.Encoding encoding = System.Text.Encoding.UTF8;
            int requiredBytes = encoding.GetByteCount(password);
            Span<byte> passwordBytes = stackalloc byte[0];
            byte[] rentedPasswordBytes = Array.Empty<byte>();

            if (requiredBytes > 128)
            {
                rentedPasswordBytes = ArrayPool<byte>.Shared.Rent(requiredBytes);
                passwordBytes = rentedPasswordBytes;
            }
            else
            {
                passwordBytes = stackalloc byte[requiredBytes];
            }

            try
            {
                fixed (byte* bytePtr = rentedPasswordBytes)
                {
                    int written = encoding.GetBytes(password, passwordBytes);

                    if (written != requiredBytes)
                    {
                        Debug.Fail("UTF8 encoding length changed between size and convert");
                        throw new CryptographicException();
                    }

                    passwordBytes = passwordBytes.Slice(0, written);

                    ReadEncryptedPkcs8(
                        validOids,
                        source,
                        passwordBytes,
                        keyReader,
                        out bytesRead,
                        out ret);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);

                if (rentedPasswordBytes.Length > 0)
                {
                    ArrayPool<byte>.Shared.Return(rentedPasswordBytes);
                }
            }
        }

        internal static void ReadEncryptedPkcs8<TRet, TParsed>(
            string[] validOids,
            ReadOnlySpan<byte> source,
            ReadOnlySpan<byte> passwordBytes,
            KeyReader<TRet, TParsed> keyReader,
            out int bytesRead,
            out TRet ret)
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(source.Length);
            source.CopyTo(buf);
            Memory<byte> rwTmp = buf.AsMemory(0, source.Length);
            ReadOnlyMemory<byte> tmp = rwTmp;

            try
            {
                ReadEncryptedPkcs8(validOids, tmp, passwordBytes, keyReader, out bytesRead, out ret);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(rwTmp.Span);
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        internal static void ReadEncryptedPkcs8<TRet, TParsed>(
            string[] validOids,
            ReadOnlyMemory<byte> source,
            ReadOnlySpan<byte> passwordBytes,
            KeyReader<TRet, TParsed> keyReader,
            out int bytesRead,
            out TRet ret)
        {
            EncryptedPrivateKeyInfo epki =
                AsnSerializer.Deserialize<EncryptedPrivateKeyInfo>(source, AsnEncodingRules.BER, out int read);

            // No supported encryption algorithms produce more bytes of decryption output than there
            // were of decryption input.
            byte[] decrypted = ArrayPool<byte>.Shared.Rent(epki.EncryptedData.Length);
            Memory<byte> decryptedMemory = decrypted;

            try
            {
                int decryptedBytes = PasswordBasedEncryption.Decrypt(
                    epki.EncryptionAlgorithm,
                    passwordBytes,
                    epki.EncryptedData.Span,
                    decrypted);

                decryptedMemory = decryptedMemory.Slice(0, decryptedBytes);

                ReadPkcs8(
                    validOids,
                    decryptedMemory,
                    keyReader,
                    out int innerRead,
                    out ret);

                if (innerRead != decryptedMemory.Length)
                {
                    ret = default;
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                bytesRead = read;
            }
            catch (CryptographicException e)
            {
                throw new CryptographicException(SR.Cryptography_Pkcs8_EncryptedReadFailed, e);
            }
        }

        internal static unsafe bool TryWriteEncryptedPkcs8(
            bool createArray,
            ReadOnlySpan<char> password,
            byte[] privateKeyInfoBlob,
            int privateKeyInfoBlobLength,
            Pkcs8.EncryptionAlgorithm encryptionAlgorithm,
            HashAlgorithmName pbkdf2Prf,
            int pbkdf2IterationCount,
            Span<byte> destination,
            out int bytesWritten,
            out byte[] createdArray)
        {
            System.Text.Encoding encoding = System.Text.Encoding.UTF8;
            int requiredBytes = encoding.GetByteCount(password);
            Span<byte> passwordBytes = stackalloc byte[0];
            byte[] rentedPasswordBytes = Array.Empty<byte>();

            if (requiredBytes > 128)
            {
                rentedPasswordBytes = ArrayPool<byte>.Shared.Rent(requiredBytes);
                passwordBytes = rentedPasswordBytes;
            }
            else
            {
                passwordBytes = stackalloc byte[requiredBytes];
            }

            try
            {
                fixed (byte* bytePtr = rentedPasswordBytes)
                {
                    int written = encoding.GetBytes(password, passwordBytes);

                    if (written != requiredBytes)
                    {
                        Debug.Fail("UTF8 encoding length changed between size and convert");
                        throw new CryptographicException();
                    }

                    passwordBytes = passwordBytes.Slice(0, written);

                    return TryWriteEncryptedPkcs8(
                        createArray,
                        passwordBytes,
                        privateKeyInfoBlob,
                        privateKeyInfoBlobLength,
                        encryptionAlgorithm,
                        pbkdf2Prf,
                        pbkdf2IterationCount,
                        destination,
                        out bytesWritten,
                        out createdArray);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);

                if (rentedPasswordBytes.Length > 0)
                {
                    ArrayPool<byte>.Shared.Return(rentedPasswordBytes);
                }
            }
        }

        internal static bool TryWriteEncryptedPkcs8(
            bool createArray,
            ReadOnlySpan<byte> passwordBytes,
            byte[] privateKeyInfoBlob,
            int privateKeyInfoBlobLength,
            Pkcs8.EncryptionAlgorithm encryptionAlgorithm,
            HashAlgorithmName pbkdf2Prf,
            int pbkdf2IterationCount,
            Span<byte> destination,
            out int bytesWritten,
            out byte[] createdArray)
        {
            return PasswordBasedEncryption.TryWriteEncryptedPkcs8(
                createArray,
                passwordBytes,
                privateKeyInfoBlob,
                privateKeyInfoBlobLength,
                encryptionAlgorithm,
                pbkdf2Prf,
                pbkdf2IterationCount,
                destination,
                out bytesWritten,
                out createdArray);
        }
    }
}
