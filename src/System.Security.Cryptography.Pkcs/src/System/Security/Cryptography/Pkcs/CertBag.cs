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
        private CertBagAsn _decoded;

        public bool IsX509Certificate { get; }

        private CertBag(CertBagAsn decoded)
        {
            _decoded = decoded;

            IsX509Certificate = _decoded.CertId == Oids.Pkcs12X509CertBagType;
        }

        private CertBag(X509Certificate2 cert)
        {
            byte[] certData = cert.RawData;

            _decoded = new CertBagAsn
            {
                CertId = Oids.Pkcs12X509CertBagType,
                CertValue = certData,
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

        public ReadOnlyMemory<byte> RawData => _decoded.CertValue;

        public X509Certificate2 GetCertificate()
        {
            if (!IsX509Certificate)
            {
                throw new InvalidOperationException("CertBag contents are not an X.509 certificate.");
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
