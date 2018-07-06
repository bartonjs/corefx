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

        private SecretBag(ReadOnlyMemory<byte> encodedBagValue)
            : base(Oids.Pkcs12SecretBag, encodedBagValue, skipCopy: true)
        {
        }

        internal SecretBag(Oid secretTypeOid, ReadOnlyMemory<byte> secretValue)
            : this(EncodeBagValue(secretTypeOid, secretValue))
        {
            _secretTypeOid = new Oid(secretTypeOid);

            _decoded = AsnSerializer.Deserialize<SecretBagAsn>(EncodedBagValue, AsnEncodingRules.BER);
        }

        private SecretBag(SecretBagAsn secretBagAsn, ReadOnlyMemory<byte> encodedBagValue)
            : this(encodedBagValue)
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

        private static byte[] EncodeBagValue(Oid secretTypeOid, in ReadOnlyMemory<byte> secretValue)
        {
            Debug.Assert(secretTypeOid != null);

            SecretBagAsn secretBagAsn = new SecretBagAsn
            {
                SecretTypeId = secretTypeOid.Value,
                SecretValue = secretValue,
            };

            using (AsnWriter writer = AsnSerializer.Serialize(secretBagAsn, AsnEncodingRules.BER))
            {
                return writer.Encode();
            }
        }

        internal static SecretBag DecodeValue(ReadOnlyMemory<byte> bagValue)
        {
            SecretBagAsn decoded = AsnSerializer.Deserialize<SecretBagAsn>(bagValue, AsnEncodingRules.BER);
            return new SecretBag(decoded, bagValue);
        }
    }
}
