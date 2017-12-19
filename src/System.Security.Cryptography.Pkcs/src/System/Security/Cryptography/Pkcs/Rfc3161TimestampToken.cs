// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs.Asn1;
using Internal.Cryptography;

namespace System.Security.Cryptography.Pkcs
{
    public sealed class Rfc3161TimestampToken
    {
        private SignedCms _parsedDocument;

        public Rfc3161TimestampTokenInfo TokenInfo { get; private set; }

        /// <summary>
        /// Get a SignedCms representation of the RFC3161 Timestamp Token.
        /// </summary>
        /// <returns>The SignedCms representation of the RFC3161 Timestamp Token.</returns>
        /// <remarks>
        /// Successive calls to this method return the same object.
        /// The SignedCms class is mutable, but changes to that object are not reflected in the
        /// <see cref="Rfc3161TimestampToken"/> object which produced it.
        /// The value from calling <see cref="SignedCms.Encode"/> can be interpreted again as an
        /// <see cref="Rfc3161TimestampToken"/> via another call to <see cref="TryParse"/>.
        /// </remarks>
        public SignedCms AsSignedCms() => _parsedDocument;

        public bool VerifyData(ReadOnlySpan<byte> data)
        {
            HashAlgorithmName hashAlgorithmName = Helpers.GetDigestAlgorithm(TokenInfo.HashAlgorithmId);

            IncrementalHash hasher = IncrementalHash.CreateHash(hashAlgorithmName);
            hasher.AppendData(data);
            
            // SHA-2-512 is the biggest hash we currently know about.
            Span<byte> stackSpan = stackalloc byte[512 / 8];

            if (hasher.TryGetHashAndReset(stackSpan, out int bytesWritten))
            {
                return VerifyHash(stackSpan.Slice(0, bytesWritten));
            }

            // Something we understood, but is bigger than 512-bit.
            // Allocate at runtime, trip in a debug build so we can re-evaluate this.
            Debug.Fail($"TryGetHashAndReset did not fit in {stackSpan.Length} for hash {TokenInfo.HashAlgorithmId.Value}");
            return VerifyHash(hasher.GetHashAndReset());
        }

        public bool VerifyHash(ReadOnlySpan<byte> hash)
        {
            return hash.SequenceEqual(TokenInfo.GetMessageHash().Span);
        }

        public static bool TryParse(ReadOnlyMemory<byte> source, out int bytesRead, out Rfc3161TimestampToken token)
        {
            try
            {
                ContentInfoAsn contentInfo =
                    AsnSerializer.Deserialize<ContentInfoAsn>(source, AsnEncodingRules.BER, out bytesRead);

                // https://tools.ietf.org/html/rfc3161#section-2.4.2
                //
                // A TimeStampToken is as follows.  It is defined as a ContentInfo
                // ([CMS]) and SHALL encapsulate a signed data content type.
                //
                // TimeStampToken::= ContentInfo
                //   --contentType is id-signedData([CMS])
                //   --content is SignedData ([CMS])
                if (contentInfo.ContentType != Oids.Pkcs7Signed)
                {
                    bytesRead = 0;
                    token = null;
                    return false;
                }

                SignedCms cms = new SignedCms();
                cms.Decode(source);

                // The fields of type EncapsulatedContentInfo of the SignedData
                // construct have the following meanings:
                //
                // eContentType is an object identifier that uniquely specifies the
                // content type.  For a time-stamp token it is defined as:
                //
                // id-ct-TSTInfo  OBJECT IDENTIFIER ::= { iso(1) member-body(2)
                // us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 4}
                //
                // eContent is the content itself, carried as an octet string.
                // The eContent SHALL be the DER-encoded value of TSTInfo.
                if (cms.ContentInfo.ContentType.Value != Oids.TstInfo)
                {
                    bytesRead = 0;
                    token = null;
                    return false;
                }

                Rfc3161TimestampTokenInfo tokenInfo;

                if (Rfc3161TimestampTokenInfo.TryParse(cms.ContentInfo.Content, out _, out tokenInfo))
                {
                    token = new Rfc3161TimestampToken
                    {
                        _parsedDocument = cms,
                        TokenInfo = tokenInfo,
                    };

                    return true;
                }
            }
            catch (CryptographicException)
            {
            }

            bytesRead = 0;
            token = null;
            return false;
        }
    }
}
