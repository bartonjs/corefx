// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs.Asn1;
using System.Security.Cryptography.X509Certificates;
using Internal.Cryptography;

namespace System.Security.Cryptography.Pkcs
{
    public sealed class Pkcs12SafeContents : IEnumerable<Pkcs12SafeBag>
    {
        private ReadOnlyMemory<byte> _encrypted;
        private List<Pkcs12SafeBag> _bags;

        public ConfidentialityMode DataConfidentialityMode { get; private set; }
        public bool IsReadOnly { get; }

        public Pkcs12SafeContents()
        {
        }

        internal Pkcs12SafeContents(ContentInfoAsn contentInfoAsn)
        {
            IsReadOnly = true;

            switch (contentInfoAsn.ContentType)
            {
                case Oids.Pkcs7Encrypted:
                    DataConfidentialityMode = ConfidentialityMode.Password;
                    _encrypted = contentInfoAsn.Content;
                    break;
                case Oids.Pkcs7Enveloped:
                    DataConfidentialityMode = ConfidentialityMode.PublicKey;
                    _encrypted = contentInfoAsn.Content;
                    break;
                case Oids.Pkcs7Data:
                    DataConfidentialityMode = ConfidentialityMode.None;
                    _bags = ReadBags(Helpers.DecodeOctetString(contentInfoAsn.Content));
                    break;
                default:
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }
        }

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

        public void DecryptEnveloped(X509Certificate2Collection extraStore = null)
        {
            EnvelopedCms cms = new EnvelopedCms();
            cms.Decode(_encrypted.ToArray());
            cms.Decrypt(extraStore);

            _bags = ReadBags(cms.ContentInfo.Content);
            DataConfidentialityMode = ConfidentialityMode.None;
        }

        public IEnumerator<Pkcs12SafeBag> GetEnumerator()
        {
            if (DataConfidentialityMode != ConfidentialityMode.None &&
                DataConfidentialityMode != ConfidentialityMode.Unknown)
            {
                throw new InvalidOperationException("Cannot enumerate the contents of an encrypted or enveloped SafeContents.");
            }

            return _bags.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        public bool TryDecryptInto(
            ReadOnlySpan<char> password,
            Memory<byte> destination,
            out int bytesWritten)
        {
            throw null;
        }

        public bool TryDecryptEnvelopedInto(
            Memory<byte> destination,
            out int bytesWritten,
            X509Certificate2Collection extraStore = null)
        {
            throw null;
        }

        private static List<Pkcs12SafeBag> ReadBags(ReadOnlyMemory<byte> serialized)
        {
            SafeBagAsn[] serializedBags =
                AsnSerializer.Deserialize<SafeBagAsn[]>(serialized, AsnEncodingRules.BER);

            if (serializedBags.Length == 0)
            {
                return new List<Pkcs12SafeBag>(0);
            }

            List<Pkcs12SafeBag> bags = new List<Pkcs12SafeBag>(serializedBags.Length);

            for (int i = 0; i < serializedBags.Length; i++)
            {
                ReadOnlyMemory<byte> bagValue = serializedBags[i].BagValue;
                Pkcs12SafeBag bag = null;

                try
                {
                    switch (serializedBags[i].BagId)
                    {
                        case Oids.Pkcs12CertBag:
                            bag = CertBag.DecodeValue(bagValue);
                            break;
                        case Oids.Pkcs12ShroudedKeyBag:
                            bag = new ShroudedKeyBag(bagValue);
                            break;
                    }
                }
                catch (CryptographicException)
                {
                }

                if (bag == null)
                {
                    bag = new UnknownBag(bagValue);
                }

                bag.Attributes = SignerInfo.MakeAttributeCollection(serializedBags[i].BagAttributes);
                bags.Add(bag);
            }

            return bags;
        }

        public enum ConfidentialityMode
        {
            Unknown = 0,
            None = 1,
            Password = 2,
            PublicKey = 3,
        }
    }
}
