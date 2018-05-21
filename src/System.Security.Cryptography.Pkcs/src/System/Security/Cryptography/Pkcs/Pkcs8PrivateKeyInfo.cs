// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs.Asn1;
using Internal.Cryptography;

namespace System.Security.Cryptography.Pkcs
{
    public sealed partial class Pkcs8PrivateKeyInfo
    {
        public string AlgorithmId { get; }
        public ReadOnlyMemory<byte> AlgorithmParameters { get; }
        public CryptographicAttributeObjectCollection Attributes { get; }
        public ReadOnlyMemory<byte> PrivateKeyBytes { get; }

        public Pkcs8PrivateKeyInfo(
            string algorithmId,
            ReadOnlyMemory<byte> algorithmParameters,
            ReadOnlyMemory<byte> privateKey,
            bool skipCopies = false)
        {
            AlgorithmId = algorithmId;
            AlgorithmParameters = skipCopies ? algorithmParameters : algorithmParameters.ToArray();
            PrivateKeyBytes = skipCopies ? privateKey : privateKey.ToArray();
            Attributes = new CryptographicAttributeObjectCollection();
        }

        private Pkcs8PrivateKeyInfo(
            string algorithmId,
            ReadOnlyMemory<byte> algorithmParameters,
            ReadOnlyMemory<byte> privateKey,
            CryptographicAttributeObjectCollection attributes)
        {
            AlgorithmId = algorithmId;
            AlgorithmParameters = algorithmParameters;
            PrivateKeyBytes = privateKey;
            Attributes = attributes;
        }

        public static Pkcs8PrivateKeyInfo Create(AsymmetricAlgorithm privateKey)
        {
            byte[] pkcs8 = privateKey.ExportPkcs8PrivateKey();
            return Decode(pkcs8, out _, skipCopy: true);
        }

        public static Pkcs8PrivateKeyInfo Decode(
            ReadOnlyMemory<byte> source, out int bytesRead, bool skipCopy = false)
        {
            if (!skipCopy)
            {
                AsnReader reader = new AsnReader(source, AsnEncodingRules.BER);
                source = reader.GetEncodedValue().ToArray();
            }

            PrivateKeyInfo privateKeyInfo =
                AsnSerializer.Deserialize<PrivateKeyInfo>(source, AsnEncodingRules.BER, out bytesRead);

            return new Pkcs8PrivateKeyInfo(
                privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Value,
                privateKeyInfo.PrivateKeyAlgorithm.Parameters.GetValueOrDefault(),
                privateKeyInfo.PrivateKey,
                SignerInfo.MakeAttributeCollection(privateKeyInfo.Attributes));
        }

        public byte[] Encode()
        {
            using (AsnWriter writer = WritePkcs8())
            {
                return writer.Encode();
            }
        }

        public byte[] Encrypt(ReadOnlySpan<char> password, PbeParameters pbeParameters)
        {
            using (AsnWriter writer = WritePkcs8())
            {
                throw null;
            }
        }

        public byte[] Encrypt(ReadOnlySpan<byte> passwordBytes, PbeParameters pbeParameters) => throw null;

        public bool TryEncode(Span<byte> destination, out int bytesWritten)
        {
            using (AsnWriter writer = WritePkcs8())
            {
                return writer.TryEncode(destination, out bytesWritten);
            }
        }

        public bool TryEncrypt(ReadOnlySpan<char> password, PbeParameters pbeParameters, Span<byte> destination,
            out int bytesWritten) => throw null;

        public bool TryEncrypt(ReadOnlySpan<byte> passwordBytes, PbeParameters pbeParameters, Span<byte> destination,
            out int bytesWritten) => throw null;

        public static void Decrypt(
            ReadOnlySpan<char> password, ReadOnlyMemory<byte> source, out int bytesRead) => throw null;

        public static void Decrypt(
            ReadOnlySpan<byte> passwordBytes, ReadOnlyMemory<byte> source, out int bytesRead) => throw null;

        private AsnWriter WritePkcs8()
        {
            PrivateKeyInfo info = new PrivateKeyInfo
            {
                PrivateKeyAlgorithm =
                {
                    Algorithm = new Oid(AlgorithmId, AlgorithmId),
                },
                PrivateKey = PrivateKeyBytes,
            };

            if (AlgorithmParameters.Length > 0)
            {
                info.PrivateKeyAlgorithm.Parameters = AlgorithmParameters;
            }

            if (Attributes.Count > 0)
            {
                info.Attributes = Helpers.NormalizeSet(CmsSigner.BuildAttributes(Attributes).ToArray());
            }

            // Write in BER in case any of the provided fields was BER.
            return AsnSerializer.Serialize(info, AsnEncodingRules.BER);
        }
    }

    // https://tools.ietf.org/html/rfc5208#section-5
    //
    // PrivateKeyInfo ::= SEQUENCE {
    //   version                   Version,
    //   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
    //   privateKey                PrivateKey,
    //   attributes           [0]  IMPLICIT Attributes OPTIONAL }
    // 
    // Version ::= INTEGER
    // PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
    // PrivateKey ::= OCTET STRING
    // Attributes ::= SET OF Attribute
    [StructLayout(LayoutKind.Sequential)]
    internal struct PrivateKeyInfo
    {
        public byte Version;

        public AlgorithmIdentifierAsn PrivateKeyAlgorithm;

        [OctetString]
        public ReadOnlyMemory<byte> PrivateKey;

        [ExpectedTag(0)]
        [OptionalValue]
        public AttributeAsn[] Attributes;
    }
}
