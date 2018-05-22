// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests
{
    public static class Pkcs8PrivateKeyInfoTests
    {
        [Fact]
        public static void EnsureAttributesParse()
        {
            var certData = (CertLoaderFromRawData)Certificates.ECDsaP256Win;
            Pkcs12Info pkcs12Info = Pkcs12Info.Decode(certData.PfxData, out _);
            ShroudedKeyBag bag = (ShroudedKeyBag)pkcs12Info.AuthenticatedSafe[0].GetBags().Single();

            Pkcs8PrivateKeyInfo pkcs8Info = Pkcs8PrivateKeyInfo.DecryptAndDecode(
                certData.Password,
                bag.EncryptedPkcs8PrivateKey,
                out _);

            Assert.Equal(1, pkcs8Info.Attributes.Count);
            Assert.Equal("2.5.29.15", pkcs8Info.Attributes[0].Oid.Value);

            var ku = new X509KeyUsageExtension(pkcs8Info.Attributes[0].Values[0], false);
            Assert.Equal(X509KeyUsageFlags.DigitalSignature, ku.KeyUsages);
        }

        [Fact]
        public static void EnsureAttributesRoundtrip()
        {
            Pkcs8PrivateKeyInfo pkcs8Info;

            using (ECDsa ecdsa = ECDsa.Create())
            {
                pkcs8Info = Pkcs8PrivateKeyInfo.Create(ecdsa);
            }

            string description = DateTimeOffset.UtcNow.ToString();
            pkcs8Info.Attributes.Add(new Pkcs9DocumentDescription(description));

            byte[] encoded = pkcs8Info.Encode();

            Pkcs8PrivateKeyInfo pkcs8Info2 = Pkcs8PrivateKeyInfo.Decode(encoded, out _, skipCopy: true);
            Assert.Equal(pkcs8Info.AlgorithmId.Value, pkcs8Info2.AlgorithmId.Value);

            Assert.Equal(
                pkcs8Info.AlgorithmParameters.Value.ByteArrayToHex(),
                pkcs8Info2.AlgorithmParameters.Value.ByteArrayToHex());

            Assert.Equal(
                pkcs8Info.PrivateKeyBytes.ByteArrayToHex(),
                pkcs8Info2.PrivateKeyBytes.ByteArrayToHex());

            Assert.Equal(1, pkcs8Info2.Attributes.Count);

            Pkcs9DocumentDescription descAttr =
                Assert.IsType<Pkcs9DocumentDescription>(pkcs8Info2.Attributes[0].Values[0]);

            Assert.Equal(description, descAttr.DocumentDescription);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public static void Decode_SkipCopyIsRespected(bool skipCopy)
        {
            Pkcs8PrivateKeyInfo pkcs8Info;

            using (ECDsa ecdsa = ECDsa.Create())
            {
                pkcs8Info = Pkcs8PrivateKeyInfo.Create(ecdsa);
            }

            byte[] encoded = pkcs8Info.Encode();
            ReadOnlySpan<byte> encodedSpan = encoded;
            Pkcs8PrivateKeyInfo pkcs8Info2 = Pkcs8PrivateKeyInfo.Decode(encoded, out _, skipCopy);

            if (skipCopy)
            {
                Assert.True(
                    encodedSpan.Overlaps(pkcs8Info2.AlgorithmParameters.Value.Span),
                    "AlgorihmParameters overlaps");

                Assert.True(
                    encodedSpan.Overlaps(pkcs8Info2.PrivateKeyBytes.Span),
                    "PrivateKeyBytes overlaps");
            }
            else
            {
                Assert.False(
                    encodedSpan.Overlaps(pkcs8Info2.AlgorithmParameters.Value.Span),
                    "AlgorihmParameters overlaps");

                Assert.False(
                    encodedSpan.Overlaps(pkcs8Info2.PrivateKeyBytes.Span),
                    "PrivateKeyBytes overlaps");
            }
        }
    }
}
