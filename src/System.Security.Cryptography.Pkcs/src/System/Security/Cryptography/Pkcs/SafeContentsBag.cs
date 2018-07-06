// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
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
            Debug.Assert(SafeContents != null);

            using (AsnWriter writer = SafeContents.Encode())
            {
                return writer.TryEncode(destination, out bytesWritten);
            }
        }

        public static SafeContentsBag CreateEncrypted(
            Pkcs12SafeContents safeContents,
            ReadOnlySpan<byte> passwordBytes,
            PbeParameters pbeParameters)
        {
            if (safeContents == null)
                throw new ArgumentNullException(nameof(safeContents));
            if (pbeParameters == null)
                throw new ArgumentNullException(nameof(pbeParameters));
            if (pbeParameters.IterationCount < 1)
                throw new ArgumentOutOfRangeException(nameof(pbeParameters.IterationCount));

            PasswordBasedEncryption.ValidatePbeParameters(
                pbeParameters,
                ReadOnlySpan<char>.Empty,
                passwordBytes);

            return CreateEncrypted(
                safeContents,
                ReadOnlySpan<char>.Empty,
                passwordBytes,
                pbeParameters);
        }

        public static SafeContentsBag CreateEncrypted(
            Pkcs12SafeContents safeContents,
            ReadOnlySpan<char> password,
            PbeParameters pbeParameters)
        {
            if (safeContents == null)
                throw new ArgumentNullException(nameof(safeContents));
            if (pbeParameters == null)
                throw new ArgumentNullException(nameof(pbeParameters));
            if (pbeParameters.IterationCount < 1)
                throw new ArgumentOutOfRangeException(nameof(pbeParameters.IterationCount));

            PasswordBasedEncryption.ValidatePbeParameters(
                pbeParameters,
                password,
                ReadOnlySpan<byte>.Empty);

            return CreateEncrypted(
                safeContents,
                password,
                ReadOnlySpan<byte>.Empty,
                pbeParameters);
        }

        private static SafeContentsBag CreateEncrypted(
            Pkcs12SafeContents safeContents,
            ReadOnlySpan<char> password,
            ReadOnlySpan<byte> passwordBytes,
            PbeParameters pbeParameters)
        {
            Debug.Assert(safeContents != null);
            Debug.Assert(pbeParameters != null);

            byte[] encrypted = safeContents.Encrypt(password, passwordBytes, pbeParameters);

            Pkcs12SafeContents encryptedCopy = new Pkcs12SafeContents(
                new ContentInfoAsn
                {
                    ContentType = Oids.Pkcs7Encrypted,
                    Content = encrypted,
                });

            return new SafeContentsBag
            {
                SafeContents = encryptedCopy,
            };
        }

        public static SafeContentsBag CreateUnencrypted(Pkcs12SafeContents safeContents)
        {
            if (safeContents == null)
                throw new ArgumentNullException(nameof(safeContents));

            ContentInfoAsn contentInfo = safeContents.EncodeToContentInfo();
            Pkcs12SafeContents copy = new Pkcs12SafeContents(contentInfo);

            return new SafeContentsBag
            {
                SafeContents = copy,
            };
        }
    }
}
