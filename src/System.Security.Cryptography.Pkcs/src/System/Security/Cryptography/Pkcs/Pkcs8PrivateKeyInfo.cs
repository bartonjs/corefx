// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography.Pkcs
{
    public sealed partial class Pkcs8PrivateKeyInfo
    {
        // Could be Oid, if we want.
        public string AlgorithmId { get; }
        public ReadOnlyMemory<byte> AlgorithmParameters { get; }
        public CryptographicAttributeObjectCollection Attributes { get; }

        public ReadOnlyMemory<byte> PrivateKeyBytes { get; }

        public Pkcs8PrivateKeyInfo(DSA privateKey)
        {
        }

        public Pkcs8PrivateKeyInfo(ECDsa privateKey)
        {
        }

        public Pkcs8PrivateKeyInfo(ECDiffieHellman privateKey)
        {
        }

        public Pkcs8PrivateKeyInfo(RSA privateKey)
        {
        }

        public Pkcs8PrivateKeyInfo(
            string algorithmId,
            ReadOnlyMemory<byte> algorithmParameters,
            ReadOnlyMemory<byte> privateKey,
            bool skipCopies = false)
        {
        }

        public static void Decode(
            ReadOnlyMemory<byte> source, out int bytesRead, bool skipCopy = false) => throw null;

        public byte[] Encode() => throw null;
        public byte[] Encrypt(ReadOnlySpan<char> password, PbeParameters pbeParameters) => throw null;
        public byte[] Encrypt(ReadOnlySpan<byte> passwordBytes, PbeParameters pbeParameters) => throw null;
        public bool TryEncode(Span<byte> destination, out int bytesWritten) => throw null;

        public bool TryEncrypt(ReadOnlySpan<char> password, PbeParameters pbeParameters, Span<byte> destination,
            out int bytesWritten) => throw null;

        public bool TryEncrypt(ReadOnlySpan<byte> passwordBytes, PbeParameters pbeParameters, Span<byte> destination,
            out int bytesWritten) => throw null;

        public static void Decrypt(
            ReadOnlySpan<char> password, ReadOnlyMemory<byte> source, out int bytesRead) => throw null;

        public static void Decrypt(
            ReadOnlySpan<byte> passwordBytes, ReadOnlyMemory<byte> source, out int bytesRead) => throw null;
    }
}
