// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs.Asn1;
using System.Security.Cryptography.X509Certificates;
using Internal.Cryptography;

namespace System.Security.Cryptography.Pkcs
{
    public sealed class CertBag : Pkcs12SafeBag
    {
        private Oid _certTypeOid;
        private readonly CertBagAsn _decoded;

        public bool IsX509Certificate { get; }

        private CertBag(CertBagAsn decoded)
            : base(Oids.Pkcs12CertBag)
        {
            _decoded = decoded;

            IsX509Certificate = _decoded.CertId == Oids.Pkcs12X509CertBagType;
        }

        /// <summary>
        /// Create a CertBag for a specified certificate type and encoding.
        /// </summary>
        /// <param name="certificateType">The identifier for the certificate type</param>
        /// <param name="encodedCertificate">The encoded value</param>
        /// <param name="skipCopy">
        ///   <c>true</c> to store the <paramref name="encodedCertificate"/> value,
        ///   <c>false</c> to store a copy of the data <paramref name="encodedCertificate"/> represents.
        /// </param>
        /// <remarks>
        /// No validation is done to ensure that the <paramref name="encodedCertificate"/> value is
        /// correct for the indicated <paramref name="certificateType"/>.  Note that for X.509
        /// public-key certificates the correct encoding for a CertBag value is to wrap the
        /// DER-encoded certificate in an OCTET STRING.
        /// </remarks>
        public CertBag(
            Oid certificateType,
            ReadOnlyMemory<byte> encodedCertificate,
            bool skipCopy = false)
            : base(Oids.Pkcs12CertBag)
        {
            if (certificateType == null)
                throw new ArgumentNullException(nameof(certificateType));

            _decoded = new CertBagAsn
            {
                CertId = certificateType.Value,
                CertValue = skipCopy ? encodedCertificate : encodedCertificate.ToArray(),
            };

            _certTypeOid = new Oid(certificateType);
            IsX509Certificate = _decoded.CertId == Oids.Pkcs12X509CertBagType;
        }

        internal CertBag(X509Certificate2 cert)
            : base(Oids.Pkcs12CertBag)
        {
            byte[] certData = cert.RawData;

            _decoded = new CertBagAsn
            {
                CertId = Oids.Pkcs12X509CertBagType,
                CertValue = PkcsPal.Instance.EncodeOctetString(certData),
            };

            IsX509Certificate = true;
        }

        public Oid GetCertificateType()
        {
            if (_certTypeOid == null)
            {
                _certTypeOid = new Oid(_decoded.CertId);
            }

            return new Oid(_certTypeOid);
        }

        public ReadOnlyMemory<byte> EncodedCertificate => _decoded.CertValue;

        public X509Certificate2 GetCertificate()
        {
            if (!IsX509Certificate)
            {
                throw new InvalidOperationException(SR.Cryptography_Pkcs12_CertBagNotX509);
            }

            return new X509Certificate2(Helpers.DecodeOctetString(_decoded.CertValue).ToArray());
        }

        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
        {
            using (AsnWriter writer = AsnSerializer.Serialize(_decoded, AsnEncodingRules.DER))
            {
                return writer.TryEncode(destination, out bytesWritten);
            }
        }

        internal static CertBag DecodeValue(ReadOnlyMemory<byte> bagValue)
        {
            CertBagAsn decoded = AsnSerializer.Deserialize<CertBagAsn>(bagValue, AsnEncodingRules.BER);
            return new CertBag(decoded);
        }
    }
}
