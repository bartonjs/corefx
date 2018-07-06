// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography.Pkcs
{
    public sealed class KeyBag : Pkcs12SafeBag
    {
        public ReadOnlyMemory<byte> Pkcs8PrivateKey { get; }

        public KeyBag(ReadOnlyMemory<byte> pkcs8PrivateKey, bool skipCopy=false)
            : base(Oids.Pkcs12KeyBag)
        {
            // Read to ensure that there is precisely one legally encoded value.
            AsnReader reader = new AsnReader(pkcs8PrivateKey, AsnEncodingRules.BER);
            reader.GetEncodedValue();
            reader.ThrowIfNotEmpty();

            Pkcs8PrivateKey = skipCopy ? pkcs8PrivateKey : pkcs8PrivateKey.ToArray();
        }

        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
        {
            if (destination.Length < Pkcs8PrivateKey.Length)
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = Pkcs8PrivateKey.Length;
            Pkcs8PrivateKey.Span.CopyTo(destination);
            return true;
        }
    }
}
