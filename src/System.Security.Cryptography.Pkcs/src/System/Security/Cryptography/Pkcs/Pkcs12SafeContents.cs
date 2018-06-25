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
                throw new InvalidOperationException(SR.Cryptography_Pkcs12_SafeContentsIsReadOnly);

            if (_bags == null)
            {
                _bags = new List<Pkcs12SafeBag>();
            }

            _bags.Add(safeBag);
        }

        public KeyBag AddKeyUnencrypted(ReadOnlyMemory<byte> pkcs8PrivateKey) => throw null;
        public SecretBag AddSecret(Oid secretType, ReadOnlyMemory<byte> secretValue) => throw null;

        public void Decrypt(ReadOnlySpan<char> password)
        {
            if (DataConfidentialityMode != ConfidentialityMode.Password)
            {
                throw new InvalidOperationException(
                    SR.Format(
                        SR.Cryptography_Pkcs12_WrongModeForDecrypt,
                        ConfidentialityMode.Password,
                        DataConfidentialityMode));
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

            List<Pkcs12SafeBag> bags;
            int encryptedValueLength = encryptedData.EncryptedContentInfo.EncryptedContent.Value.Length;
            
            // Don't use the array pool because the parsed bags are going to have ReadOnlyMemory projections
            // over this data.
            byte[] destination = new byte[encryptedValueLength];

            int written = PasswordBasedEncryption.Decrypt(
                encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm,
                password,
                ReadOnlySpan<byte>.Empty,
                encryptedData.EncryptedContentInfo.EncryptedContent.Value.Span,
                destination);

            try
            {
                bags = ReadBags(destination.AsMemory(0, written));
            }
            catch
            {
                CryptographicOperations.ZeroMemory(destination.AsSpan(0, written));
                throw;
            }

            _encrypted = ReadOnlyMemory<byte>.Empty;
            _bags = bags;
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
