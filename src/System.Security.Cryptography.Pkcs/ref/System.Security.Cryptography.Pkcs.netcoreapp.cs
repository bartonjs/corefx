// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// ------------------------------------------------------------------------------
// Changes to this file must follow the http://aka.ms/api-review process.
// ------------------------------------------------------------------------------

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;

namespace System.Security.Cryptography.Pkcs
{
    public sealed partial class CertBag : Pkcs12SafeBag
    {
        private CertBag() : base(null) { }
        public bool IsX509Certificate { get; }
        public ReadOnlyMemory<byte> RawData { get; }
        public Oid GetCertificateType() => throw null;
        public X509Certificate2 GetCertificate() => throw null;
        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten) => throw null;
    }
    public sealed partial class KeyBag : Pkcs12SafeBag
    {
        private KeyBag() : base(null) { }
        public ReadOnlyMemory<byte> Pkcs8PrivateKey { get; }
        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten) => throw null;
    }
    public sealed partial class Pkcs12Builder
    {
        public bool IsSealed { get; }
        public void AddSafeContentsEncrypted(Pkcs12SafeContents safeContents, ReadOnlySpan<char> password, PbeParameters pbeParameters) => throw null;
        public void AddSafeContentsUnencrypted(Pkcs12SafeContents safeContents) => throw null;
        public byte[] Encode() => throw null;
        public void SealAndMac(ReadOnlySpan<char> password, HashAlgorithmName hashAlgorithm, int iterationCount) => throw null;
        public bool TryEncode(Span<byte> destination, out int bytesWritten) => throw null;
    }
    public sealed partial class Pkcs12Info
    {
        private Pkcs12Info() { }
        public ReadOnlyCollection<Pkcs12SafeContents> AuthenticatedSafe { get; }
        public IntegrityMode DataIntegrityMode { get; }
        public bool VerifyMac(ReadOnlySpan<char> password) => throw null;
        public static Pkcs12Info Decode(ReadOnlyMemory<byte> encodedBytes, out int bytesConsumed, bool skipCopy=false) => throw null;
        public enum IntegrityMode
        {
            Unknown = 0,
            Password = 1,
            PublicKey = 2,
        }
    }
    public abstract partial class Pkcs12SafeBag
    {
        protected Pkcs12SafeBag(string bagIdValue) { }
        public CryptographicAttributeObjectCollection Attributes { get; }
        public byte[] Encode() => throw null;
        public Oid GetBagId() => throw null;
        public bool TryEncode(Span<byte> destination, out int bytesWritten) => throw null;
        protected abstract bool TryEncodeValue(Span<byte> destination, out int bytesWritten);
    }
    public sealed partial class Pkcs12SafeContents
    {
        public ConfidentialityMode DataConfidentialityMode { get; }
        public bool IsReadOnly { get; }
        public void AddSafeBag(Pkcs12SafeBag safeBag) => throw null;
        public CertBag AddCertificate(X509Certificate2 certificate) => throw null;
        public KeyBag AddKeyUnencrypted(ReadOnlyMemory<byte> pkcs8PrivateKey) => throw null;
        public SecretBag AddSecret(Oid secretType, ReadOnlyMemory<byte> secretValue) => throw null;
        public void Decrypt(ReadOnlySpan<char> password) => throw null;
        public IEnumerable<Pkcs12SafeBag> GetBags() => throw null;
        public enum ConfidentialityMode
        {
            Unknown = 0,
            None = 1,
            Password = 2,
            PublicKey = 3,
        }
    }
    public sealed partial class Pkcs8PrivateKeyInfo
    {
        public Oid AlgorithmId { get; }
        public ReadOnlyMemory<byte>? AlgorithmParameters { get; }
        public CryptographicAttributeObjectCollection Attributes { get; }
        public ReadOnlyMemory<byte> PrivateKeyBytes { get; }
        public Pkcs8PrivateKeyInfo(Oid algorithmId, ReadOnlyMemory<byte>? algorithmParameters, ReadOnlyMemory<byte> privateKey, bool skipCopies = false) { }
        public static Pkcs8PrivateKeyInfo Create(AsymmetricAlgorithm privateKey) => throw null;
        public static Pkcs8PrivateKeyInfo Decode(ReadOnlyMemory<byte> source, out int bytesRead, bool skipCopy = false) => throw null;
        public byte[] Encode() => throw null;
        public byte[] Encrypt(ReadOnlySpan<char> password, PbeParameters pbeParameters) => throw null;
        public byte[] Encrypt(ReadOnlySpan<byte> passwordBytes, PbeParameters pbeParameters) => throw null;
        public bool TryEncode(Span<byte> destination, out int bytesWritten) => throw null;
        public bool TryEncrypt(ReadOnlySpan<char> password, PbeParameters pbeParameters, Span<byte> destination, out int bytesWritten) => throw null;
        public bool TryEncrypt(ReadOnlySpan<byte> passwordBytes, PbeParameters pbeParameters, Span<byte> destination, out int bytesWritten) => throw null;
        public static Pkcs8PrivateKeyInfo DecryptAndDecode(ReadOnlySpan<char> password, ReadOnlyMemory<byte> source, out int bytesRead) => throw null;
        public static Pkcs8PrivateKeyInfo DecryptAndDecode(ReadOnlySpan<byte> passwordBytes, ReadOnlyMemory<byte> source, out int bytesRead) => throw null;
    }
    public sealed partial class Rfc3161TimestampRequest
    {
        private Rfc3161TimestampRequest() { }
        public int Version => throw null;
        public ReadOnlyMemory<byte> GetMessageHash() => throw null;
        public Oid HashAlgorithmId => throw null;
        public Oid RequestedPolicyId => throw null;
        public bool RequestSignerCertificate => throw null;
        public ReadOnlyMemory<byte>? GetNonce() => throw null;
        public bool HasExtensions => throw null;
        public X509ExtensionCollection GetExtensions() => throw null;
        public byte[] Encode() => throw null;
        public bool TryEncode(Span<byte> destination, out int bytesWritten) => throw null;
        public Rfc3161TimestampToken ProcessResponse(ReadOnlyMemory<byte> responseBytes, out int bytesConsumed) => throw null;
        public static Rfc3161TimestampRequest CreateFromData(ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm, Oid requestedPolicyId = null, ReadOnlyMemory<byte>? nonce = null, bool requestSignerCertificates = false, X509ExtensionCollection extensions = null) => throw null;
        public static Rfc3161TimestampRequest CreateFromHash(ReadOnlyMemory<byte> hash, HashAlgorithmName hashAlgorithm, Oid requestedPolicyId = null, ReadOnlyMemory<byte>? nonce = null, bool requestSignerCertificates = false, X509ExtensionCollection extensions = null) => throw null;
        public static Rfc3161TimestampRequest CreateFromHash(ReadOnlyMemory<byte> hash, Oid hashAlgorithmId, Oid requestedPolicyId = null, ReadOnlyMemory<byte>? nonce = null, bool requestSignerCertificates = false, X509ExtensionCollection extensions = null) => throw null;
        public static Rfc3161TimestampRequest CreateFromSignerInfo(SignerInfo signerInfo, HashAlgorithmName hashAlgorithm, Oid requestedPolicyId = null, ReadOnlyMemory<byte>? nonce = null, bool requestSignerCertificates = false, X509ExtensionCollection extensions = null) => throw null;
        public static bool TryDecode(ReadOnlyMemory<byte> encodedBytes, out Rfc3161TimestampRequest request, out int bytesConsumed) => throw null;
    }
    public sealed partial class Rfc3161TimestampToken
    {
        private Rfc3161TimestampToken() { }
        public Rfc3161TimestampTokenInfo TokenInfo => throw null;
        public SignedCms AsSignedCms() => throw null;
        public bool VerifySignatureForHash(ReadOnlySpan<byte> hash, HashAlgorithmName hashAlgorithm, out X509Certificate2 signerCertificate, X509Certificate2Collection extraCandidates = null) => throw null;
        public bool VerifySignatureForHash(ReadOnlySpan<byte> hash, Oid hashAlgorithmId, out X509Certificate2 signerCertificate, X509Certificate2Collection extraCandidates = null) => throw null;
        public bool VerifySignatureForData(ReadOnlySpan<byte> data, out X509Certificate2 signerCertificate, X509Certificate2Collection extraCandidates = null) => throw null;
        public bool VerifySignatureForSignerInfo(SignerInfo signerInfo, out X509Certificate2 signerCertificate, X509Certificate2Collection extraCandidates = null) => throw null;
        public static bool TryDecode(ReadOnlyMemory<byte> encodedBytes, out Rfc3161TimestampToken token, out int bytesConsumed) => throw null;
    }
    public sealed partial class Rfc3161TimestampTokenInfo
    {
        public Rfc3161TimestampTokenInfo(Oid policyId, Oid hashAlgorithmId, ReadOnlyMemory<byte> messageHash, ReadOnlyMemory<byte> serialNumber, DateTimeOffset timestamp, long? accuracyInMicroseconds=null, bool isOrdering=false, ReadOnlyMemory<byte>? nonce=null, ReadOnlyMemory<byte>? timestampAuthorityName=null, X509ExtensionCollection extensions =null) { throw null; }
        public int Version => throw null;
        public Oid PolicyId=> throw null;
        public Oid HashAlgorithmId => throw null;
        public ReadOnlyMemory<byte> GetMessageHash() { throw null; }
        public ReadOnlyMemory<byte> GetSerialNumber() { throw null; }
        public DateTimeOffset Timestamp => throw null;
        public long? AccuracyInMicroseconds => throw null;
        public bool IsOrdering => throw null;
        public ReadOnlyMemory<byte>? GetNonce() { throw null; }
        public ReadOnlyMemory<byte>? GetTimestampAuthorityName() { throw null; }
        public bool HasExtensions => throw null;
        public X509ExtensionCollection GetExtensions() { throw null; }
        public byte[] Encode() => throw null;
        public bool TryEncode(Span<byte> destination, out int bytesWritten) => throw null;
        public static bool TryDecode(ReadOnlyMemory<byte> encodedBytes, out Rfc3161TimestampTokenInfo timestampTokenInfo, out int bytesConsumed) { throw null; }
    }
    public sealed partial class SafeContentsBag : Pkcs12SafeBag
    {
        private SafeContentsBag() : base(null) { }
        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten) => throw null;
        public Pkcs12SafeContents SafeContents { get; }
        public static SafeContentsBag CreateEncrypted(Pkcs12SafeContents safeContents, ReadOnlySpan<char> password, PbeParameters pbeParameters) => throw null;
        public static SafeContentsBag CreateUnencrypted(Pkcs12SafeContents contents) => throw null;
    }
    public sealed partial class SecretBag : Pkcs12SafeBag
    {
        private SecretBag() : base(null) { }
        public Oid GetSecretType() => throw null;
        public ReadOnlyMemory<byte> SecretValue { get; }
        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten) => throw null;
    }
    public sealed partial class ShroudedKeyBag : Pkcs12SafeBag
    {
        public ShroudedKeyBag(ReadOnlyMemory<byte> encryptedPkcs8PrivateKey, bool skipCopy=false) : base(null) { }
        public ReadOnlyMemory<byte> EncryptedPkcs8PrivateKey { get; }
        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten) => throw null;
    }
    public sealed partial class SignerInfo
    {
        public Oid SignatureAlgorithm => throw null;
        public byte[] GetSignature() => throw null;
    }
}
