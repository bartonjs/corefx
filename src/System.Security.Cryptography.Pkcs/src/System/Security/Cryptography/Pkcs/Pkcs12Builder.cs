// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs.Asn1;
using Internal.Cryptography;

namespace System.Security.Cryptography.Pkcs
{
    public sealed class Pkcs12Builder
    {
        private ReadOnlyMemory<byte> _sealedData;
        private List<ContentInfoAsn> _contents;

        public bool IsSealed => !_sealedData.IsEmpty;

        public unsafe void AddSafeContentsEncrypted(
            Pkcs12SafeContents safeContents,
            ReadOnlySpan<char> password,
            Pkcs8.EncryptionAlgorithm encryptionAlgorithm,
            HashAlgorithmName hashAlgorithm,
            int iterationCount)
        {
            if (safeContents == null)
                throw new ArgumentNullException(nameof(safeContents));
            if (iterationCount < 1)
                throw new ArgumentOutOfRangeException(nameof(iterationCount));
            if (IsSealed)
                throw new InvalidOperationException("Cannot add new SafeContents when the PFX is sealed.");

            if (_contents == null)
            {
                _contents = new List<ContentInfoAsn>();
            }

            AsnWriter writer = null;

            using (AsnWriter contentsWriter = safeContents.Encode())
            {
                ReadOnlySpan<byte> contentsSpan = contentsWriter.EncodeAsSpan();
                
                PasswordBasedEncryption.InitiateEncryption(
                    encryptionAlgorithm,
                    hashAlgorithm,
                    out SymmetricAlgorithm cipher,
                    out string hmacOid,
                    out string encryptionAlgorithmOid,
                    out bool isPkcs12);

                int cipherBlockBytes = cipher.BlockSize / 8;
                byte[] encryptedRent = ArrayPool<byte>.Shared.Rent(contentsSpan.Length + cipherBlockBytes);
                Span<byte> encryptedSpan = Span<byte>.Empty;
                Span<byte> iv = stackalloc byte[cipherBlockBytes];
                Span<byte> salt = stackalloc byte[16];
                RandomNumberGenerator.Fill(salt);

                try
                {
                    int written = PasswordBasedEncryption.Encrypt(
                        password,
                        ReadOnlySpan<byte>.Empty,
                        cipher,
                        isPkcs12,
                        contentsSpan,
                        hashAlgorithm,
                        iterationCount,
                        salt,
                        encryptedRent,
                        iv);

                    encryptedSpan = encryptedRent.AsSpan(0, written);

                    writer = new AsnWriter(AsnEncodingRules.DER);

                    // EncryptedData
                    writer.PushSequence();

                    // version
                    // Since we're not writing unprotected attributes, version=0
                    writer.WriteInteger(0);

                    // encryptedContentInfo
                    {
                        writer.PushSequence();
                        writer.WriteObjectIdentifier(Oids.Pkcs7Data);

                        PasswordBasedEncryption.WritePbeAlgorithmIdentifier(
                            writer,
                            isPkcs12,
                            encryptionAlgorithmOid,
                            salt,
                            iterationCount,
                            hmacOid,
                            iv);

                        writer.WriteOctetString(
                            new Asn1Tag(TagClass.ContextSpecific, 0),
                            encryptedSpan);

                        writer.PopSequence();
                    }

                    writer.PopSequence();

                    _contents.Add(
                        new ContentInfoAsn
                        {
                            ContentType = Oids.Pkcs7Encrypted,
                            Content = writer.Encode(),
                        });
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(encryptedSpan);
                    ArrayPool<byte>.Shared.Return(encryptedRent);
                    writer?.Dispose();
                }
            }
        }

        public void AddSafeContentsEnveloped(
            Pkcs12SafeContents safeContents,
            CmsRecipient recipient)
        {
            if (safeContents == null)
                throw new ArgumentNullException(nameof(safeContents));
            if (recipient == null)
                throw new ArgumentNullException(nameof(recipient));
            if (IsSealed)
                throw new InvalidOperationException("Cannot add new SafeContents when the PFX is sealed.");

            if (_contents == null)
            {
                _contents = new List<ContentInfoAsn>();
            }

            throw new NotImplementedException();
        }

        public void AddSafeContentsUnencrypted(Pkcs12SafeContents safeContents)
        {
            if (safeContents == null)
                throw new ArgumentNullException(nameof(safeContents));
            if (IsSealed)
                throw new InvalidOperationException("Cannot add new SafeContents when the PFX is sealed.");

            if (_contents == null)
            {
                _contents = new List<ContentInfoAsn>();
            }

            using (AsnWriter contentsWriter = safeContents.Encode())
            using (AsnWriter valueWriter = new AsnWriter(AsnEncodingRules.DER))
            {
                valueWriter.WriteOctetString(contentsWriter.EncodeAsSpan());

                _contents.Add(
                    new ContentInfoAsn
                    {
                        ContentType = Oids.Pkcs7Data,
                        Content = valueWriter.Encode(),
                    });
            }
        }

        public byte[] Encode()
        {
            if (!IsSealed)
            {
                throw new InvalidOperationException("Cannot encode the data until it is sealed.");
            }

            return _sealedData.ToArray();
        }

        public void SealAndMac(
            ReadOnlySpan<char> password,
            HashAlgorithmName hashAlgorithm,
            int iterationCount)
        {
            if (iterationCount < 1)
                throw new ArgumentOutOfRangeException(nameof(iterationCount));
            if (IsSealed)
                throw new InvalidOperationException("Cannot re-seal the data.");

            ContentInfoAsn[] contents = _contents?.ToArray() ?? Array.Empty<ContentInfoAsn>();

            byte[] rentedAuthSafe = null;
            Span<byte> authSafeSpan = default;
            byte[] rentedMac = null;
            Span<byte> macSpan = default;
            Span<byte> salt = stackalloc byte[0];

            try
            {
                using (AsnWriter writer = AsnSerializer.Serialize(contents, AsnEncodingRules.BER))
                using (IncrementalHash hasher = IncrementalHash.CreateHash(hashAlgorithm))
                {
                    ReadOnlySpan<byte> encodedSpan = writer.EncodeAsSpan();

                    rentedAuthSafe = ArrayPool<byte>.Shared.Rent(encodedSpan.Length);
                    encodedSpan.CopyTo(rentedAuthSafe);
                    authSafeSpan = rentedAuthSafe.AsSpan(0, encodedSpan.Length);

                    // Get an array of the proper size for the hash.
                    byte[] macKey = hasher.GetHashAndReset();
                    rentedMac = ArrayPool<byte>.Shared.Rent(macKey.Length);
                    macSpan = rentedMac.AsSpan(0, macKey.Length);

                    // Since the biggest supported hash is SHA-2-512 (64 bytes), the
                    // 128-byte cap here shouldn't ever come into play.
                    salt = stackalloc byte[Math.Min(macKey.Length, 128)];
                    RandomNumberGenerator.Fill(salt);

                    Pkcs12Kdf.DeriveMacKey(
                        password,
                        hashAlgorithm,
                        (uint)iterationCount,
                        salt,
                        macKey);

                    using (IncrementalHash mac = IncrementalHash.CreateHMAC(hashAlgorithm, macKey))
                    {
                        mac.AppendData(encodedSpan);

                        if (!mac.TryGetHashAndReset(macSpan, out int bytesWritten) || bytesWritten != macSpan.Length)
                        {
                            Debug.Fail($"TryGetHashAndReset wrote {bytesWritten} of {macSpan.Length} bytes");
                            throw new CryptographicException();
                        }
                    }
                }

                // https://tools.ietf.org/html/rfc7292#section-4
                //
                // PFX ::= SEQUENCE {
                //   version    INTEGER {v3(3)}(v3,...),
                //   authSafe   ContentInfo,
                //   macData    MacData OPTIONAL
                // }
                using (AsnWriter writer = new AsnWriter(AsnEncodingRules.BER))
                {
                    writer.PushSequence();

                    writer.WriteInteger(3);

                    writer.PushSequence();
                    {
                        writer.WriteObjectIdentifier(Oids.Pkcs7Data);

                        Asn1Tag contextSpecific0 = new Asn1Tag(TagClass.ContextSpecific, 0);

                        writer.PushSequence(contextSpecific0);
                        {
                            writer.WriteOctetString(authSafeSpan);
                            writer.PopSequence(contextSpecific0);
                        }

                        writer.PopSequence();
                    }

                    // https://tools.ietf.org/html/rfc7292#section-4
                    // 
                    // MacData ::= SEQUENCE {
                    //   mac        DigestInfo,
                    //   macSalt    OCTET STRING,
                    //   iterations INTEGER DEFAULT 1
                    //   -- Note: The default is for historical reasons and its use is
                    //   -- deprecated.
                    // }
                    writer.PushSequence();
                    {
                        writer.PushSequence();
                        {
                            writer.PushSequence();
                            {
                                writer.WriteObjectIdentifier(Helpers.GetOidFromHashAlgorithm(hashAlgorithm));
                                writer.PopSequence();
                            }

                            writer.WriteOctetString(macSpan);
                            writer.PopSequence();
                        }

                        writer.WriteOctetString(salt);

                        if (iterationCount > 1)
                        {
                            writer.WriteInteger(iterationCount);
                        }

                        writer.PopSequence();
                    }

                    writer.PopSequence();
                    _sealedData = writer.Encode();
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(macSpan);
                CryptographicOperations.ZeroMemory(authSafeSpan);

                if (rentedMac != null)
                {
                    ArrayPool<byte>.Shared.Return(rentedMac);
                }

                if (rentedAuthSafe != null)
                {
                    ArrayPool<byte>.Shared.Return(rentedAuthSafe);
                }
            }
        }

        public void SealAndSign(CmsSigner signer)
        {
            if (signer == null)
            {
                throw new ArgumentNullException(nameof(signer));
            }

            if (IsSealed)
            {
                throw new InvalidOperationException("Cannot re-seal the data.");
            }

            throw new NotImplementedException();
        }

        public bool TryEncode(Span<byte> destination, out int bytesWritten)
        {
            if (!IsSealed)
            {
                throw new InvalidOperationException("Cannot encode the data until it is sealed.");
            }

            if (destination.Length < _sealedData.Length)
            {
                bytesWritten = 0;
                return false;
            }

            _sealedData.Span.CopyTo(destination);
            bytesWritten = _sealedData.Length;
            return true;
        }
    }
}
