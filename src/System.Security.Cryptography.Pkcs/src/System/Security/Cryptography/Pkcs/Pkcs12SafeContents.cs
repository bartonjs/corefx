// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace System.Security.Cryptography.Pkcs
{
    public sealed partial class Pkcs12SafeContents : IEnumerable<Pkcs12SafeBag>
    {
        public ConfidentialityMode DataConfidentialityMode { get; }
        public bool IsReadOnly { get; }
        public void AddSafeBag(Pkcs12SafeBag safeBag) => throw null;
        public CertBag AddCertificate(X509Certificate2 certificate) => throw null;
        public KeyBag AddKeyUnencrypted(ReadOnlyMemory<byte> pkcs8PrivateKey) => throw null;
        public SafeContentsBag AddNestedSafeContentsEncrypted(Pkcs12SafeContents safeContents, ReadOnlySpan<char> password, Pkcs8.EncryptionAlgorithm encryptionAlgorithm, HashAlgorithmName hashAlgorithm, int iterationCount) => throw null;
        public SafeContentsBag AddNestedSafeContentsEnveloped(Pkcs12SafeContents safeContents, CmsRecipient recipient) => throw null;
        public SafeContentsBag AddNestedSafeContentsUnencrypted(Pkcs12SafeContents safeContents) => throw null;
        public ShroudedKeyBag AddShroudedKey(ReadOnlyMemory<byte> encryptedPkcs8PrivateKey) => throw null;
        public ShroudedKeyBag AddShroudedKey(DSA key, ReadOnlySpan<char> password, Pkcs8.EncryptionAlgorithm encryptionAlgorithm, HashAlgorithmName hashAlgorithm, int iterationCount) => throw null;
        public ShroudedKeyBag AddShroudedKey(ECDiffieHellman key, ReadOnlySpan<char> password, Pkcs8.EncryptionAlgorithm encryptionAlgorithm, HashAlgorithmName hashAlgorithm, int iterationCount) => throw null;
        public ShroudedKeyBag AddShroudedKey(ECDsa key, ReadOnlySpan<char> password, Pkcs8.EncryptionAlgorithm encryptionAlgorithm, HashAlgorithmName hashAlgorithm, int iterationCount) => throw null;
        public ShroudedKeyBag AddShroudedKey(RSA key, ReadOnlySpan<char> password, Pkcs8.EncryptionAlgorithm encryptionAlgorithm, HashAlgorithmName hashAlgorithm, int iterationCount) => throw null;
        public SecretBag AddSecret(Oid secretType, ReadOnlyMemory<byte> secretValue) => throw null;
        public void Decrypt(ReadOnlySpan<char> password) => throw null;
        public void DecryptEnveloped(System.Security.Cryptography.X509Certificates.X509Certificate2Collection extraStore = null) => throw null;
        public IEnumerator<Pkcs12SafeBag> GetEnumerator() => throw null;
        IEnumerator IEnumerable.GetEnumerator() => throw null;
        public bool TryDecryptInto(ReadOnlySpan<char> password, Memory<byte> destination, out int bytesWritten) => throw null;
        public bool TryDecryptEnvelopedInto(Memory<byte> destination, out int bytesWritten, System.Security.Cryptography.X509Certificates.X509Certificate2Collection extraStore = null) => throw null;
        public enum ConfidentialityMode
        {
            Unknown = 0,
            None = 1,
            Password = 2,
            PublicKey = 3,
        }
    }
}
