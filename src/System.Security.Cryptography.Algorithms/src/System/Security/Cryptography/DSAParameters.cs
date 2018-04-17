// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
    // DSAParameters is serializable so that one could pass the public parameters
    // across a remote call, but we explicitly make the private key X non-serializable
    // so you cannot accidently send it along with the public parameters.
    public struct DSAParameters
    {
        public byte[] P;
        public byte[] Q;
        public byte[] G;
        public byte[] Y;
        public byte[] J;
        public byte[] X;
        public byte[] Seed;
        public int Counter;

        public static DSAParameters FromPkcs8PrivateKey(System.ReadOnlySpan<byte> source, out int bytesRead) => throw null;
        public static DSAParameters FromEncryptedPkcs8PrivateKey(System.ReadOnlySpan<char> password, System.ReadOnlySpan<byte> source, out int bytesRead) => throw null;
        public static DSAParameters FromEncryptedPkcs8PrivateKey(System.ReadOnlySpan<byte> passwordBytes, System.ReadOnlySpan<byte> source, out int bytesRead) => throw null;
        public static DSAParameters FromSubjectPublicKeyInfo(System.ReadOnlySpan<byte> source, out int bytesRead) => throw null;
        public byte[] ToPkcs8PrivateKey() => throw null;
        public byte[] ToEncryptedPkcs8PrivateKey(System.ReadOnlySpan<char> password, HashAlgorithmName pbkdf2HashAlgorithm, int pbkdf2IterationCount, Pkcs8.EncryptionAlgorithm encryptionAlgorithm) => throw null;
        public byte[] ToEncryptedPkcs8PrivateKey(System.ReadOnlySpan<byte> passwordBytes, HashAlgorithmName pbkdf2HashAlgorithm, int pbkdf2IterationCount, Pkcs8.EncryptionAlgorithm encryptionAlgorithm) => throw null;
        public byte[] ToSubjectPublicKeyInfo() => throw null;
        public bool TryWritePkcs8PrivateKey(System.Span<byte> destination, out int bytesWritten) => throw null;
        public bool TryWriteEncryptedPkcs8PrivateKey(System.ReadOnlySpan<char> password, HashAlgorithmName pbkdf2HashAlgorithm, int pbkdf2IterationCount, Pkcs8.EncryptionAlgorithm encryptionAlgorithm, System.Span<byte> destination, out int bytesWritten) => throw null;
        public bool TryWriteEncryptedPkcs8PrivateKey(System.ReadOnlySpan<byte> passwordBytes, HashAlgorithmName pbkdf2HashAlgorithm, int pbkdf2IterationCount, Pkcs8.EncryptionAlgorithm encryptionAlgorithm, System.Span<byte> destination, out int bytesWritten) => throw null;
        public bool TryWriteSubjectPublicKeyInfo(System.Span<byte> destination, out int bytesWritten) => throw null;
    }
}
