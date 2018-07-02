// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs.Asn1;

namespace System.Security.Cryptography.Pkcs
{
    public sealed class SafeContentsBag : Pkcs12SafeBag
    {
        public Pkcs12SafeContents SafeContents { get; private set; }

        private SafeContentsBag()
            : base(Oids.Pkcs12SafeContentsBag)
        {
        }

        internal static SafeContentsBag Decode(ReadOnlyMemory<byte> encoded)
        {
            ContentInfoAsn contentInfo =
                AsnSerializer.Deserialize<ContentInfoAsn>(encoded, AsnEncodingRules.BER);

            Pkcs12SafeContents contents = new Pkcs12SafeContents(contentInfo);

            return new SafeContentsBag
            {
                SafeContents = contents
            };
        }

        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
        {
            throw null;
        }

        public static SafeContentsBag CreateEncrypted(
            Pkcs12SafeContents safeContents,
            ReadOnlySpan<byte> passwordBytes,
            PbeParameters pbeParameters)
        {
            throw null;
        }

        public static SafeContentsBag CreateEncrypted(
            Pkcs12SafeContents safeContents,
            ReadOnlySpan<char> password,
            PbeParameters pbeParameters)
        {
            throw null;
        }

        public static SafeContentsBag CreateUnencrypted(Pkcs12SafeContents contents)
        {
            throw null;
        }
    }
}
