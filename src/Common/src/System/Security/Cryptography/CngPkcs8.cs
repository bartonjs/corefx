// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography
{
    internal static partial class CngPkcs8
    {
        // Windows 7, 8, and 8.1 don't support PBES2 export, so use
        // the 3DES-192 scheme from PKCS12-PBE whenever deferring to the system.
        private static readonly PbeParameters s_platformParameters =
            new PbeParameters(
                PbeEncryptionAlgorithm.TripleDes3KeyPkcs12,
                HashAlgorithmName.SHA1,
                10000);

        internal static bool CanUsePasswordBytes(PbeEncryptionAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case PbeEncryptionAlgorithm.Aes128Cbc:
                case PbeEncryptionAlgorithm.Aes192Cbc:
                case PbeEncryptionAlgorithm.Aes256Cbc:
                    return true;
                case PbeEncryptionAlgorithm.TripleDes3KeyPkcs12:
                    return false;
            }

            Debug.Assert(
                algorithm == PbeEncryptionAlgorithm.Unknown,
                $"Unhandled algorithm '{algorithm}'");
            return false;
        }

        internal static bool IsPlatformScheme(PbeParameters pbeParameters)
        {
            Debug.Assert(pbeParameters != null);

            return pbeParameters.EncryptionAlgorithm == s_platformParameters.EncryptionAlgorithm &&
                   pbeParameters.HashAlgorithm == s_platformParameters.HashAlgorithm;
        }

        internal static byte[] ExportEncryptedPkcs8PrivateKey(
            AsymmetricAlgorithm key,
            ReadOnlySpan<byte> passwordBytes,
            PbeParameters pbeParameters)
        {
            AsnWriter writer = RewriteEncryptedPkcs8PrivateKey(
                key,
                passwordBytes,
                pbeParameters);

            using (writer)
            {
                return writer.Encode();
            }
        }

        internal static bool TryExportEncryptedPkcs8PrivateKey(
            AsymmetricAlgorithm key,
            ReadOnlySpan<byte> passwordBytes,
            PbeParameters pbeParameters,
            Span<byte> destination,
            out int bytesWritten)
        {
            AsnWriter writer = RewriteEncryptedPkcs8PrivateKey(
                key,
                passwordBytes,
                pbeParameters);

            using (writer)
            {
                return writer.TryEncode(destination, out bytesWritten);
            }
        }

        internal static byte[] ExportEncryptedPkcs8PrivateKey(
            AsymmetricAlgorithm key,
            ReadOnlySpan<char> password,
            PbeParameters pbeParameters)
        {
            AsnWriter writer = RewriteEncryptedPkcs8PrivateKey(
                key,
                password,
                pbeParameters);

            using (writer)
            {
                return writer.Encode();
            }
        }

        internal static bool TryExportEncryptedPkcs8PrivateKey(
            AsymmetricAlgorithm key,
            ReadOnlySpan<char> password,
            PbeParameters pbeParameters,
            Span<byte> destination,
            out int bytesWritten)
        {
            AsnWriter writer = RewriteEncryptedPkcs8PrivateKey(
                key,
                password,
                pbeParameters);

            using (writer)
            {
                return writer.TryEncode(destination, out bytesWritten);
            }
        }

        private static AsnWriter RewriteEncryptedPkcs8PrivateKey(
            AsymmetricAlgorithm key,
            ReadOnlySpan<byte> passwordBytes,
            PbeParameters pbeParameters)
        {
            Debug.Assert(pbeParameters != null);

            // For RSA:
            //  * 512-bit key needs ~400 bytes
            //  * 16384-bit key needs ~10k bytes.
            //  * KeySize (bits) should avoid re-rent.
            //
            // For DSA:
            //  * 512-bit key needs ~300 bytes.
            //  * 1024-bit key needs ~400 bytes.
            //  * 2048-bit key needs ~700 bytes.
            //  * KeySize (bits) should avoid re-rent.
            //
            // For ECC:
            //  * secp256r1 needs ~200 bytes (named) or ~450 (explicit)
            //  * secp384r1 needs ~250 bytes (named) or ~600 (explicit)
            //  * secp521r1 needs ~300 bytes (named) or ~730 (explicit)
            //  * KeySize (bits) should avoid re-rent for named, and probably
            //    gets one re-rent for explicit.
            byte[] rented = ArrayPool<byte>.Shared.Rent(key.KeySize);
            int rentWritten = 0;

            // If we use 6 bits from each byte, that's 22 * 6 = 132
            Span<char> randomString = stackalloc char[22];

            try
            {
                FillRandomAsciiString(randomString);

                while (!key.TryExportEncryptedPkcs8PrivateKey(
                    randomString,
                    s_platformParameters,
                    rented,
                    out rentWritten))
                {
                    int size = rented.Length;
                    ArrayPool<byte>.Shared.Return(rented);
                    rented = ArrayPool<byte>.Shared.Rent(checked(size * 2));
                }

                return KeyFormatHelper.ReencryptPkcs8(
                    randomString,
                    rented.AsMemory(0, rentWritten),
                    passwordBytes,
                    pbeParameters);
            }
            finally
            {
                randomString.Clear();
                CryptographicOperations.ZeroMemory(rented.AsSpan(0, rentWritten));
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        private static AsnWriter RewriteEncryptedPkcs8PrivateKey(
            AsymmetricAlgorithm key,
            ReadOnlySpan<char> password,
            PbeParameters pbeParameters)
        {
            Debug.Assert(pbeParameters != null);

            byte[] rented = ArrayPool<byte>.Shared.Rent(key.KeySize);
            int rentWritten = 0;

            try
            {
                while (!key.TryExportEncryptedPkcs8PrivateKey(
                    password,
                    s_platformParameters,
                    rented,
                    out rentWritten))
                {
                    int size = rented.Length;
                    ArrayPool<byte>.Shared.Return(rented);
                    rented = ArrayPool<byte>.Shared.Rent(checked(size * 2));
                }

                return KeyFormatHelper.ReencryptPkcs8(
                    password,
                    rented.AsMemory(0, rentWritten),
                    password,
                    pbeParameters);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(rented.AsSpan(0, rentWritten));
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        private static void FillRandomAsciiString(Span<char> destination)
        {
            Debug.Assert(destination.Length < 128);
            Span<byte> randomKey = stackalloc byte[destination.Length];
            RandomNumberGenerator.Fill(randomKey);

            for (int i = 0; i < randomKey.Length; i++)
            {
                // 33 (!) up to 33 + 63 = 96 (`)
                destination[i] = (char)(33 + (randomKey[i] & 0b0011_1111));
            }
        }
    }
}
