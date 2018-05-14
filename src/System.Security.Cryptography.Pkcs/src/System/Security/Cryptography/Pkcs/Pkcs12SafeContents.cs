// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs.Asn1;
using System.Security.Cryptography.X509Certificates;
using Internal.Cryptography;

namespace System.Security.Cryptography.Pkcs
{
    public sealed class Pkcs12SafeContents
    {
        private ReadOnlyMemory<byte> _encrypted;
        private List<Pkcs12SafeBag> _bags;

        public ConfidentialityMode DataConfidentialityMode { get; private set; }
        public bool IsReadOnly { get; }

        public Pkcs12SafeContents()
        {
            DataConfidentialityMode = ConfidentialityMode.None;
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

        public void AddSafeBag(Pkcs12SafeBag safeBag)
        {
            if (safeBag == null)
                throw new ArgumentNullException(nameof(safeBag));

            if (IsReadOnly)
                throw new InvalidOperationException();

            if (_bags == null)
            {
                _bags = new List<Pkcs12SafeBag>();
            }

            _bags.Add(safeBag);
        }

        public CertBag AddCertificate(X509Certificate2 certificate)
        {
            CertBag bag = new CertBag(certificate);
            AddSafeBag(bag);
            return bag;
        }

        public KeyBag AddKeyUnencrypted(ReadOnlyMemory<byte> pkcs8PrivateKey)
        {
            KeyBag bag = new KeyBag(pkcs8PrivateKey);
            AddSafeBag(bag);
            return bag;
        }

        public SafeContentsBag AddNestedSafeContentsEncrypted(Pkcs12SafeContents safeContents, ReadOnlySpan<char> password, PbeParameters pbeParameters) => throw null;
        public SafeContentsBag AddNestedSafeContentsEnveloped(Pkcs12SafeContents safeContents, CmsRecipient recipient) => throw null;
        public SafeContentsBag AddNestedSafeContentsUnencrypted(Pkcs12SafeContents safeContents) => throw null;

        public ShroudedKeyBag AddShroudedKey(ReadOnlyMemory<byte> encryptedPkcs8PrivateKey)
        {
            ShroudedKeyBag bag = new ShroudedKeyBag(encryptedPkcs8PrivateKey);
            AddSafeBag(bag);
            return bag;
        }

        public ShroudedKeyBag AddShroudedKey(DSA key, ReadOnlySpan<char> password, PbeParameters pbeParameters) => throw null;
        public ShroudedKeyBag AddShroudedKey(ECDiffieHellman key, ReadOnlySpan<char> password, PbeParameters pbeParameters) => throw null;
        public ShroudedKeyBag AddShroudedKey(ECDsa key, ReadOnlySpan<char> password, PbeParameters pbeParameters) => throw null;
        public ShroudedKeyBag AddShroudedKey(RSA key, ReadOnlySpan<char> password, PbeParameters pbeParameters) => throw null;
        public SecretBag AddSecret(Oid secretType, ReadOnlyMemory<byte> secretValue) => throw null;

        public void Decrypt(ReadOnlySpan<char> password)
        {
            bool success = TryDecryptInto(
                password,
                Memory<byte>.Empty,
                true,
                out _);

            Debug.Assert(success, "TryDecryptInto failed in allocation mode.");
        }

        public void DecryptEnveloped(X509Certificate2Collection extraStore = null)
        {
            if (DataConfidentialityMode != ConfidentialityMode.PublicKey)
            {
                throw new InvalidOperationException(
                    $"Cannot apply public key-based decryption when DataConfidentialityMode is {DataConfidentialityMode}.");
            }

            EnvelopedCms cms = new EnvelopedCms();
            cms.Decode(_encrypted.ToArray());
            cms.Decrypt(extraStore);

            _bags = ReadBags(cms.ContentInfo.Content);
            DataConfidentialityMode = ConfidentialityMode.None;
        }

        public IEnumerable<Pkcs12SafeBag> GetBags()
        {
            if (DataConfidentialityMode != ConfidentialityMode.None)
            {
                throw new InvalidOperationException(
                    "Cannot enumerate the contents of an encrypted or enveloped SafeContents.");
            }

            if (_bags == null)
            {
                return Enumerable.Empty<Pkcs12SafeBag>();
            }

            return _bags.AsReadOnly();
        }

        public bool TryDecryptInto(
            ReadOnlySpan<char> password,
            Memory<byte> destination,
            out int bytesWritten)
        {
            return TryDecryptInto(
                password,
                destination,
                false,
                out bytesWritten);
        }

        public bool TryDecryptEnvelopedInto(
            Memory<byte> destination,
            out int bytesWritten,
            X509Certificate2Collection extraStore = null)
        {
            throw new NotImplementedException();
        }

        private bool TryDecryptInto(
            ReadOnlySpan<char> password,
            Memory<byte> destination,
            bool allocate,
            out int bytesWritten)
        {
            if (DataConfidentialityMode != ConfidentialityMode.Password)
            {
                throw new InvalidOperationException(
                    $"Cannot apply password-based decryption when DataConfidentialityMode is {DataConfidentialityMode}.");
            }

            EncryptedDataAsn encryptedData =
                AsnSerializer.Deserialize<EncryptedDataAsn>(_encrypted, AsnEncodingRules.BER);

            // https://tools.ietf.org/html/rfc5652#section-8
            if (encryptedData.Version != 0 && encryptedData.Version != 2)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            // Since the contents are supposed to be the BER-encoding of an instance of
            // SafeContents (https://tools.ietf.org/html/rfc7292#section-4.1) that implies the
            // content type is simply "data", and that content is present.
            if (encryptedData.EncryptedContentInfo.ContentType != Oids.Pkcs7Data)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            if (!encryptedData.EncryptedContentInfo.EncryptedContent.HasValue)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            int encryptedValueLength = encryptedData.EncryptedContentInfo.EncryptedContent.Value.Length;

            if (allocate)
            {
                destination = new byte[encryptedValueLength];
            }
            else
            {
                if (destination.Length < encryptedValueLength)
                {
                    bytesWritten = 0;
                    return false;
                }
            }

            int written = PasswordBasedEncryption.Decrypt(
                encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm,
                password,
                ReadOnlySpan<byte>.Empty,
                encryptedData.EncryptedContentInfo.EncryptedContent.Value.Span,
                destination.Span);

            List<Pkcs12SafeBag> bags;

            try
            {
                bags = ReadBags(destination.Slice(0, written));
            }
            catch
            {
                CryptographicOperations.ZeroMemory(destination.Span.Slice(0, written));
                throw;
            }

            bytesWritten = written;
            _bags = bags;
            _encrypted = default;
            DataConfidentialityMode = ConfidentialityMode.None;

            return true;
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
                        case Oids.Pkcs12KeyBag:
                            bag = new KeyBag(bagValue);
                            break;
                        case Oids.Pkcs12ShroudedKeyBag:
                            bag = new ShroudedKeyBag(bagValue);
                            break;
                        case Oids.Pkcs12CertBag:
                            bag = CertBag.DecodeValue(bagValue);
                            break;
                        case Oids.Pkcs12CrlBag:
                            break;
                        case Oids.Pkcs12SecretBag:
                            break;
                        case Oids.Pkcs12SafeContentsBag:
                            bag = SafeContentsBag.Decode(bagValue);
                            break;
                    }
                }
                catch (CryptographicException)
                {
                }

                if (bag == null)
                {
                    bag = new UnknownBag(serializedBags[i].BagId, bagValue);
                }

                bag.Attributes = SignerInfo.MakeAttributeCollection(serializedBags[i].BagAttributes);
                bags.Add(bag);
            }

            return bags;
        }

        internal AsnWriter Encode()
        {
            AsnWriter writer;

            if (DataConfidentialityMode == ConfidentialityMode.Password ||
                DataConfidentialityMode == ConfidentialityMode.PublicKey)
            {
                writer = new AsnWriter(AsnEncodingRules.BER);
                writer.WriteEncodedValue(_encrypted);
                return writer;
            }

            Debug.Assert(DataConfidentialityMode == ConfidentialityMode.None);

            // A shrouded key bag for RSA-1024 comes in at just under 1000 bytes.
            // Most certificates are in the 1000-2300 byte range.
            // Ideally we don't need to re-rent with 4kb.
            byte[] rentedBuf = ArrayPool<byte>.Shared.Rent(4096);
            writer = new AsnWriter(AsnEncodingRules.BER);
            int maxBytesWritten = 0;

            try
            {
                writer.PushSequence();

                if (_bags != null)
                {
                    foreach (Pkcs12SafeBag safeBag in _bags)
                    {
                        int bytesWritten;

                        while (!safeBag.TryEncode(rentedBuf, out bytesWritten))
                        {
                            CryptographicOperations.ZeroMemory(rentedBuf.AsSpan(0, maxBytesWritten));
                            byte[] newRent = ArrayPool<byte>.Shared.Rent(rentedBuf.Length * 2);
                            ArrayPool<byte>.Shared.Return(rentedBuf);
                            rentedBuf = newRent;
                            maxBytesWritten = 0;
                        }

                        maxBytesWritten = Math.Max(maxBytesWritten, bytesWritten);
                        writer.WriteEncodedValue(rentedBuf.AsMemory(0, bytesWritten));
                    }
                }

                writer.PopSequence();
                return writer;
            }
            catch
            {
                writer.Dispose();
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(rentedBuf.AsSpan(0, maxBytesWritten));
                ArrayPool<byte>.Shared.Return(rentedBuf);
            }
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
