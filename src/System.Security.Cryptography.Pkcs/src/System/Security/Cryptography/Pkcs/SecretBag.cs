// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs.Asn1;

namespace System.Security.Cryptography.Pkcs
{
    public sealed class SecretBag : Pkcs12SafeBag
    {
        private Oid _secretTypeOid;
        private readonly SecretBagAsn _decoded;

        public ReadOnlyMemory<byte> SecretValue => _decoded.SecretValue;

        private SecretBag()
            : base(Oids.Pkcs12SecretBag)
        {
        }

        internal SecretBag(Oid secretTypeOid, ReadOnlyMemory<byte> secretValue, bool skipCopy=false)
            : this()
        {
            Debug.Assert(secretTypeOid != null);

            _secretTypeOid = new Oid(secretTypeOid);

            _decoded = new SecretBagAsn
            {
                SecretTypeId = secretTypeOid.Value,
                SecretValue = skipCopy ? secretValue : secretValue.ToArray(),
            };
        }

        private SecretBag(SecretBagAsn secretBagAsn)
            : this()
        {
            _decoded = secretBagAsn;
        }

        public Oid GetSecretType()
        {
            if (_secretTypeOid == null)
            {
                _secretTypeOid = new Oid(_decoded.SecretTypeId);
            }

            return new Oid(_secretTypeOid);
        }

        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
        {
            using (AsnWriter writer = AsnSerializer.Serialize(_decoded, AsnEncodingRules.BER))
            {
                return writer.TryEncode(destination, out bytesWritten);
            }
        }

        internal static SecretBag DecodeValue(ReadOnlyMemory<byte> bagValue)
        {
            SecretBagAsn decoded = AsnSerializer.Deserialize<SecretBagAsn>(bagValue, AsnEncodingRules.BER);
            return new SecretBag(decoded);
        }
    }
}
