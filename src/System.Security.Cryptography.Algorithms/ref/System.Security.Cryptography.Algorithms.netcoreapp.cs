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
        public virtual bool TryCreateSignature(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten) { throw null; }
        protected virtual bool TryHashData(ReadOnlySpan<byte> source, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) { throw null; }
        public virtual bool TrySignData(ReadOnlySpan<byte> source, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) { throw null; }
        public virtual bool VerifyData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm) { throw null; }
        public virtual bool VerifySignature(ReadOnlySpan<byte> rgbHash, ReadOnlySpan<byte> rgbSignature) { throw null; }
    }
    public abstract partial class ECDsa : System.Security.Cryptography.AsymmetricAlgorithm
    {
        protected virtual bool TryHashData(ReadOnlySpan<byte> source, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) { throw null; }
        public virtual bool TrySignData(ReadOnlySpan<byte> source, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) { throw null; }
        public virtual bool TrySignHash(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten) { throw null; }
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
        public virtual void GetBytes(System.Span<byte> data) { }
        public virtual void GetNonZeroBytes(System.Span<byte> data) { }
    }
    public abstract partial class RSA : System.Security.Cryptography.AsymmetricAlgorithm
    {
        public virtual bool TryDecrypt(System.ReadOnlySpan<byte> source, System.Span<byte> destination, RSAEncryptionPadding padding, out int bytesWritten) { throw null; }
        public virtual bool TryEncrypt(System.ReadOnlySpan<byte> source, System.Span<byte> destination, RSAEncryptionPadding padding, out int bytesWritten) { throw null; }
        protected virtual bool TryHashData(System.ReadOnlySpan<byte> source, System.Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) { throw null; }
        public virtual bool TrySignData(System.ReadOnlySpan<byte> source, System.Span<byte> destination, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, out int bytesWritten) { throw null; }
        public virtual bool TrySignHash(System.ReadOnlySpan<byte> source, System.Span<byte> destination, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, out int bytesWritten) { throw null; }
        public virtual bool VerifyData(System.ReadOnlySpan<byte> data, System.ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) { throw null; }
        public virtual bool VerifyHash(System.ReadOnlySpan<byte> hash, System.ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) { throw null; }
    }
    public abstract partial class ECDiffieHellman : System.Security.Cryptography.AsymmetricAlgorithm
    {
        protected ECDiffieHellman() { }
        public override string KeyExchangeAlgorithm { get { throw null; } }
        public abstract System.Security.Cryptography.ECDiffieHellmanPublicKey PublicKey { get; }
        public override string SignatureAlgorithm { get { throw null; } }
        public static new System.Security.Cryptography.ECDiffieHellman Create() { throw null; }
        public static System.Security.Cryptography.ECDiffieHellman Create(System.Security.Cryptography.ECCurve curve) { throw null; }
        public static System.Security.Cryptography.ECDiffieHellman Create(System.Security.Cryptography.ECParameters parameters) { throw null; }
        public static new System.Security.Cryptography.ECDiffieHellman Create(string algorithm) { throw null; }
        public byte[] DeriveKeyFromHash(System.Security.Cryptography.ECDiffieHellmanPublicKey otherPartyPublicKey, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public virtual byte[] DeriveKeyFromHash(System.Security.Cryptography.ECDiffieHellmanPublicKey otherPartyPublicKey, System.Security.Cryptography.HashAlgorithmName hashAlgorithm, byte[] secretPrepend, byte[] secretAppend) { throw null; }
        public byte[] DeriveKeyFromHmac(System.Security.Cryptography.ECDiffieHellmanPublicKey otherPartyPublicKey, System.Security.Cryptography.HashAlgorithmName hashAlgorithm, byte[] hmacKey) { throw null; }
        public virtual byte[] DeriveKeyFromHmac(System.Security.Cryptography.ECDiffieHellmanPublicKey otherPartyPublicKey, System.Security.Cryptography.HashAlgorithmName hashAlgorithm, byte[] hmacKey, byte[] secretPrepend, byte[] secretAppend) { throw null; }
        public virtual byte[] DeriveKeyMaterial(System.Security.Cryptography.ECDiffieHellmanPublicKey otherPartyPublicKey) { throw null; }
        public virtual byte[] DeriveKeyTls(System.Security.Cryptography.ECDiffieHellmanPublicKey otherPartyPublicKey, byte[] prfLabel, byte[] prfSeed) { throw null; }
        public virtual System.Security.Cryptography.ECParameters ExportExplicitParameters(bool includePrivateParameters) { throw null; }
        public virtual System.Security.Cryptography.ECParameters ExportParameters(bool includePrivateParameters) { throw null; }
        public override void FromXmlString(string xmlString) { }
        public virtual void GenerateKey(System.Security.Cryptography.ECCurve curve) { }
        public virtual void ImportParameters(System.Security.Cryptography.ECParameters parameters) { }
        public override string ToXmlString(bool includePrivateParameters) { throw null; }
    }
    public abstract partial class ECDiffieHellmanPublicKey : System.IDisposable
    {
        public virtual System.Security.Cryptography.ECParameters ExportExplicitParameters() { throw null; }
        public virtual System.Security.Cryptography.ECParameters ExportParameters() { throw null; }
    }
}
