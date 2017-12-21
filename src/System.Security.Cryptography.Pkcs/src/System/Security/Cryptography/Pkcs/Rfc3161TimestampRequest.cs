// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Internal.Cryptography;

namespace System.Security.Cryptography.Pkcs
{
    public sealed class Rfc3161TimestampRequest
    {
        private byte[] _encodedBytes;
        private Rfc3161TimeStampReq _parsedData;

        private Rfc3161TimestampRequest()
        {
        }

        public int Version => _parsedData.Version;
        public ReadOnlyMemory<byte> GetMessageHash() => _parsedData.MessageImprint.HashedMessage;
        public Oid HashAlgorithmId => _parsedData.MessageImprint.HashAlgorithm.Algorithm;
        public Oid RequestedPolicyId => _parsedData.ReqPolicy;
        public bool RequestSignerCertificate => _parsedData.CertReq;
        public ReadOnlyMemory<byte>? GetNonce() => _parsedData.Nonce;
        public bool HasExtensions => _parsedData.Extensions?.Length > 0;

        public X509ExtensionCollection GetExtensions()
        {
            var coll = new X509ExtensionCollection();

            if (!HasExtensions)
            {
                return coll;
            }

            X509ExtensionAsn[] rawExtensions = _parsedData.Extensions;

            foreach (X509ExtensionAsn rawExtension in rawExtensions)
            {
                X509Extension extension = new X509Extension(
                    rawExtension.ExtnId,
                    rawExtension.ExtnValue.ToArray(),
                    rawExtension.Critical);

                // Currently there are no extensions defined.
                // Should this dip into CryptoConfig or other extensible
                // mechanisms for the CopyTo rich type uplift?
                coll.Add(extension);
            }

            return coll;
        }

        public async Task<Rfc3161TimestampToken> SubmitRequestAsync(Uri uri, TimeSpan timeout)
        {
            if (uri == null)
                throw new ArgumentNullException(nameof(uri));
            if (!uri.IsAbsoluteUri)
                throw new ArgumentOutOfRangeException(nameof(uri), SR.Cryptography_TimestampReq_HttpOrHttps);
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
                throw new ArgumentOutOfRangeException(nameof(uri), SR.Cryptography_TimestampReq_HttpOrHttps);

            // This method implements https://tools.ietf.org/html/rfc3161#section-3.4
            try
            {
                
                HttpClient httpClient = new HttpClient
                {
                    Timeout = timeout,
                    DefaultRequestHeaders =
                    {
                        { "Content-Type", "application/timestamp-query" },
                    },
                };

                HttpResponseMessage response =
                    await httpClient.PostAsync(uri, new ReadOnlyMemoryContent(_encodedBytes));

                if (!response.IsSuccessStatusCode)
                {
                    throw new CryptographicException(
                        SR.Format(
                            SR.Cryptography_TimestampReq_HttpError,
                            (int)response.StatusCode,
                            response.StatusCode,
                            response.ReasonPhrase));
                }

                if (!response.Headers.TryGetValues("Content-Type", out IEnumerable<string> typeHeaders) ||
                    typeHeaders.Single() != "application/timestamp-reply")
                {
                    throw new CryptographicException(SR.Cryptography_TimestampReq_BadResponse);
                }

                byte[] contents = await response.Content.ReadAsByteArrayAsync();

                if (contents == null)
                {
                    throw new CryptographicException(SR.Cryptography_TimestampReq_BadResponse);
                }

                var resp = AsnSerializer.Deserialize<Rfc3161TimeStampResp>(contents, AsnEncodingRules.DER);

                if (resp.Status.Status != PkiStatus.Granted && resp.Status.Status != PkiStatus.GrantedWithMods)
                {
                    throw new CryptographicException(
                        SR.Format(
                            SR.Cryptography_TimestampReq_Failure,
                            resp.Status.Status,
                            resp.Status.FailInfo.GetValueOrDefault()));
                }

                Rfc3161TimestampToken token;

                if (Rfc3161TimestampToken.TryParse(resp.TimeStampToken.GetValueOrDefault(), out _, out token))
                {
                    return token;
                }

                throw new CryptographicException(SR.Cryptography_TimestampReq_BadResponse);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new CryptographicException(SR.Cryptography_TimestampReq_Error, e);
            }
        }

        public byte[] Encode()
        {
            return _encodedBytes.CloneByteArray();
        }

        public bool TryEncode(Span<byte> destination, out int bytesWritten)
        {
            if (destination.Length < _encodedBytes.Length)
            {
                bytesWritten = 0;
                return false;
            }

            _encodedBytes.AsSpan().CopyTo(destination);
            bytesWritten = _encodedBytes.Length;
            return true;
        }

        public static Rfc3161TimestampRequest BuildForSignerInfo(
            SignerInfo signerInfo,
            HashAlgorithmName hashAlgorithm,
            Oid requestedPolicyId = null,
            ReadOnlyMemory<byte>? nonce = null,
            bool requestSignerCertificates = false,
            X509ExtensionCollection extensions = null)
        {
            if (signerInfo == null)
            {
                throw new ArgumentNullException(nameof(signerInfo));
            }

            // https://tools.ietf.org/html/rfc3161, Appendix A.
            //
            // The value of messageImprint field within TimeStampToken shall be a
            // hash of the value of signature field within SignerInfo for the
            // signedData being time-stamped.
            return BuildForData(
                signerInfo.GetSignature(),
                hashAlgorithm,
                requestedPolicyId,
                nonce,
                requestSignerCertificates,
                extensions);
        }

        public static Rfc3161TimestampRequest BuildForData(
            ReadOnlySpan<byte> data,
            HashAlgorithmName hashAlgorithm,
            Oid requestedPolicyId = null,
            ReadOnlyMemory<byte>? nonce = null,
            bool requestSignerCertificates = false,
            X509ExtensionCollection extensions = null)
        {
            using (IncrementalHash hasher = IncrementalHash.CreateHash(hashAlgorithm))
            {
                hasher.AppendData(data);
                byte[] digest = hasher.GetHashAndReset();

                return BuildForHash(
                    digest,
                    hashAlgorithm,
                    requestedPolicyId,
                    nonce,
                    requestSignerCertificates,
                    extensions);
            }
        }

        public static Rfc3161TimestampRequest BuildForHash(
            ReadOnlyMemory<byte> hash,
            HashAlgorithmName hashAlgorithm,
            Oid requestedPolicyId = null,
            ReadOnlyMemory<byte>? nonce = null,
            bool requestSignerCertificates = false,
            X509ExtensionCollection extensions = null)
        {
            string oidStr = Helpers.GetOidFromHashAlgorithm(hashAlgorithm);
            
            return BuildForHash(
                hash,
                new Oid(oidStr),
                requestedPolicyId,
                nonce,
                requestSignerCertificates,
                extensions);
        }

        public static Rfc3161TimestampRequest BuildForHash(
            ReadOnlyMemory<byte> hash,
            Oid hashAlgorithmId,
            Oid requestedPolicyId = null,
            ReadOnlyMemory<byte>? nonce = null,
            bool requestSignerCertificates = false,
            X509ExtensionCollection extensions = null)
        {
            var req = new Rfc3161TimeStampReq
            {
                Version = 1,
                MessageImprint = new MessageImprint
                {
                    HashAlgorithm =
                    {
                        Algorithm = hashAlgorithmId,
                        Parameters = AlgorithmIdentifierAsn.ExplicitDerNull,
                    },

                    HashedMessage = hash,
                },
                ReqPolicy = requestedPolicyId,
                CertReq = requestSignerCertificates,
                Nonce = nonce,
            };

            if (extensions != null)
            {
                req.Extensions =
                    extensions.OfType<X509Extension>().Select(e => new X509ExtensionAsn(e)).ToArray();
            }

            // The RFC implies DER (see TryParse), and DER is the most widely understood given that
            // CER isn't specified.
            AsnWriter writer = AsnSerializer.Serialize(req, AsnEncodingRules.DER);

            return new Rfc3161TimestampRequest
            {
                _encodedBytes = writer.Encode(),
                _parsedData = req,
            };
        }

        public static bool TryParse(
            ReadOnlyMemory<byte> source,
            out int bytesRead,
            out Rfc3161TimestampRequest request)
        {
            try
            {
                // RFC 3161 doesn't have a concise statement that TimeStampReq will
                // be DER encoded, but under the email protocol (3.1), file protocol (3.2),
                // socket protocol (3.3) and HTTP protocol (3.4) they all say DER for the
                // transmission.
                //
                // Since nothing says BER, assume DER only.
                const AsnEncodingRules RuleSet = AsnEncodingRules.DER;

                AsnReader reader = new AsnReader(source, RuleSet);
                ReadOnlyMemory<byte> firstElement = reader.PeekEncodedValue();

                var req = AsnSerializer.Deserialize<Rfc3161TimeStampReq>(firstElement, RuleSet);

                request = new Rfc3161TimestampRequest
                {
                    _parsedData = req,
                    _encodedBytes = firstElement.ToArray(),
                };

                bytesRead = firstElement.Length;
                return true;
            }
            catch (CryptographicException)
            {
            }

            request = null;
            bytesRead = 0;
            return false;
        }
    }
}
