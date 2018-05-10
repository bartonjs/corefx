// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// ------------------------------------------------------------------------------
// Changes to this file must follow the http://aka.ms/api-review process.
// ------------------------------------------------------------------------------


namespace System.Security.Cryptography
{
    public abstract partial class DSA : System.Security.Cryptography.AsymmetricAlgorithm
    {
        public virtual bool TryCreateSignature(ReadOnlySpan<byte> hash, Span<byte> destination, out int bytesWritten) { throw null; }
        protected virtual bool TryHashData(ReadOnlySpan<byte> data, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) { throw null; }
        public virtual bool TrySignData(ReadOnlySpan<byte> data, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) { throw null; }
        public virtual bool VerifyData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm) { throw null; }
        public virtual bool VerifySignature(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature) { throw null; }
        public virtual void ImportEncryptedkcs8PrivateKey(System.ReadOnlySpan<char> password, System.ReadOnlySpan<byte> source, out int bytesRead) => throw null;
        public virtual void ImportEncryptedkcs8PrivateKey(System.ReadOnlySpan<byte> passwordBytes, System.ReadOnlySpan<byte> source, out int bytesRead) => throw null;
        public virtual byte[] ExportEncryptedPkcs8PrivateKey(System.ReadOnlySpan<char> password, HashAlgorithmName pbkdf2HashAlgorithm, int pbkdf2IterationCount, Pkcs8.EncryptionAlgorithm encryptionAlgorithm) => throw null;
        public virtual byte[] ExportEncryptedPkcs8PrivateKey(System.ReadOnlySpan<byte> passwordBytes, HashAlgorithmName pbkdf2HashAlgorithm, int pbkdf2IterationCount, Pkcs8.EncryptionAlgorithm encryptionAlgorithm) => throw null;
        public virtual bool TryExportEncryptedPkcs8PrivateKey(System.ReadOnlySpan<char> password, HashAlgorithmName pbkdf2HashAlgorithm, int pbkdf2IterationCount, Pkcs8.EncryptionAlgorithm encryptionAlgorithm, System.Span<byte> destination, out int bytesWritten) => throw null;
        public virtual bool TryExportEncryptedPkcs8PrivateKey(System.ReadOnlySpan<byte> passwordBytes, HashAlgorithmName pbkdf2HashAlgorithm, int pbkdf2IterationCount, Pkcs8.EncryptionAlgorithm encryptionAlgorithm, System.Span<byte> destination, out int bytesWritten) => throw null;
    }
    public partial struct DSAParameters
    {
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
    public abstract partial class ECDsa : System.Security.Cryptography.AsymmetricAlgorithm
    {
        protected virtual bool TryHashData(ReadOnlySpan<byte> data, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) { throw null; }
        public virtual bool TrySignData(ReadOnlySpan<byte> data, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) { throw null; }
        public virtual bool TrySignHash(ReadOnlySpan<byte> hash, Span<byte> destination, out int bytesWritten) { throw null; }
        public virtual bool VerifyData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm) { throw null; }
        public virtual bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature) { throw null; }
    }
    public sealed partial class IncrementalHash : System.IDisposable
    {
        public void AppendData(System.ReadOnlySpan<byte> data) { }
        public bool TryGetHashAndReset(System.Span<byte> destination, out int bytesWritten) { throw null; }
    }
    public abstract partial class RandomNumberGenerator : System.IDisposable
    {
        public static void Fill(Span<byte> data) => throw null;
        public virtual void GetBytes(System.Span<byte> data) { }
        public virtual void GetNonZeroBytes(System.Span<byte> data) { }
    }
    public abstract partial class RSA : System.Security.Cryptography.AsymmetricAlgorithm
    {
        public virtual bool TryDecrypt(System.ReadOnlySpan<byte> data, System.Span<byte> destination, RSAEncryptionPadding padding, out int bytesWritten) { throw null; }
        public virtual bool TryEncrypt(System.ReadOnlySpan<byte> data, System.Span<byte> destination, RSAEncryptionPadding padding, out int bytesWritten) { throw null; }
        protected virtual bool TryHashData(System.ReadOnlySpan<byte> data, System.Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) { throw null; }
        public virtual bool TrySignData(System.ReadOnlySpan<byte> data, System.Span<byte> destination, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, out int bytesWritten) { throw null; }
        public virtual bool TrySignHash(System.ReadOnlySpan<byte> hash, System.Span<byte> destination, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, out int bytesWritten) { throw null; }
        public virtual bool VerifyData(System.ReadOnlySpan<byte> data, System.ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) { throw null; }
        public virtual bool VerifyHash(System.ReadOnlySpan<byte> hash, System.ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) { throw null; }
    }
    public abstract partial class RSA : System.Security.Cryptography.AsymmetricAlgorithm
    {
        public virtual void ImportRSAPrivateKey(ReadOnlyMemory<byte> source, out int bytesWritten) => throw null;
        public virtual void ImportRSAPublicKey(ReadOnlyMemory<byte> source, out int bytesWritten) => throw null;
        public virtual byte[] ExportRSAPrivateKey() => throw null;
        public virtual byte[] ExportRSAPublicKey() => throw null;
        public virtual bool TryExportRSAPrivateKey(Span<byte> destination, out int bytesWritten) => throw null;
        public virtual bool TryExportRSAPublicKey(Span<byte> destination, out int bytesWritten) => throw null;
    }
}
