// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.ObjectModel;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace System.Security.Cryptography.Pkcs
{
    public sealed class Pkcs12Info
    {
        public ReadOnlyCollection<Pkcs12SafeContents> AuthenticatedSafe { get; private set; }
        public IntegrityMode DataIntegrityMode { get; private set; }

        private Pkcs12Info()
        {
        }

        public bool VerifyMac(ReadOnlySpan<byte> password) => throw null;

        public bool VerifySignature(X509Certificate2 signerCertificate) => throw null;

        public static Pkcs12Info Decode(
            ReadOnlyMemory<byte> encodedBytes,
            out int bytesConsumed)
        {
            AsnReader reader = new AsnReader(encodedBytes, AsnEncodingRules.BER);
            // Trim it to the first value
            encodedBytes = reader.PeekEncodedValue();

            // Copy the data
            byte[] copy = encodedBytes.ToArray();

            Pfx pfx = AsnSerializer.Deserialize<Pfx>(copy, AsnEncodingRules.BER);

            // https://tools.ietf.org/html/rfc7292#section-4 only defines version 3.
            if (pfx.Version != 3)
            {
                throw new CryptographicException("Only version 3 PFX data is supported");
            }

            throw new NotImplementedException();
            //bytesConsumed = encodedBytes.Length;
        }

        public enum IntegrityMode
        {
            Unknown,
            Password,
            PublicKey,
        }
    }
}
