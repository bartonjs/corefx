// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography.X509Certificates;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests
{
    public static class TimestampTokenTests
    {
        [Theory]
        [InlineData(nameof(TimestampTokenTestData.FreeTsaDotOrg1))]
        [InlineData(nameof(TimestampTokenTestData.Symantec1))]
        public static void ParseDocument(string testDataName)
        {
            TimestampTokenTestData testData = TimestampTokenTestData.GetTestData(testDataName);

            TestParseDocument(testData.FullTokenBytes, testData, testData.FullTokenBytes.Length);
        }

        [Theory]
        [InlineData(nameof(TimestampTokenTestData.FreeTsaDotOrg1))]
        [InlineData(nameof(TimestampTokenTestData.Symantec1))]
        public static void ParseDocument_ExcessData(string testDataName)
        {
            TimestampTokenTestData testData = TimestampTokenTestData.GetTestData(testDataName);

            int baseLen = testData.FullTokenBytes.Length;
            byte[] tooMuchData = new byte[baseLen + 30];
            testData.FullTokenBytes.CopyTo(tooMuchData);

            // Look like an octet string of the remainder of the payload.  Should be ignored.
            tooMuchData[baseLen] = 0x04;
            tooMuchData[baseLen + 1] = 28;

            TestParseDocument(tooMuchData, testData, baseLen);
        }

        private static void TestParseDocument(
            ReadOnlyMemory<byte> tokenBytes,
            TimestampTokenTestData testData,
            int? expectedBytesRead)
        {
            int bytesRead;
            Rfc3161TimestampToken token;

            Assert.True(
                Rfc3161TimestampToken.TryParse(tokenBytes, out bytesRead, out token),
                "Rfc3161TimestampToken.TryParse");

            if (expectedBytesRead != null)
            {
                Assert.Equal(expectedBytesRead.Value, bytesRead);
            }

            Assert.NotNull(token);
            TimestampTokenInfoTests.AssertEqual(testData, token.TokenInfo);

            SignedCms signedCms = token.AsSignedCms();
            Assert.NotNull(signedCms);
            Assert.Equal(Oids.TstInfo, signedCms.ContentInfo.ContentType.Value);

            Assert.Equal(
                testData.TokenInfoBytes.ByteArrayToHex(),
                signedCms.ContentInfo.Content.ByteArrayToHex());

            if (testData.EmbeddedSigningCertificate != null)
            {
                Assert.NotNull(signedCms.SignerInfos[0].Certificate);

                Assert.Equal(
                    testData.EmbeddedSigningCertificate.Value.ByteArrayToHex(),
                    signedCms.SignerInfos[0].Certificate.RawData.ByteArrayToHex());

                // Assert.NoThrow
                signedCms.CheckSignature(true);
            }
            else
            {
                Assert.Null(signedCms.SignerInfos[0].Certificate);

                using (var signerCert = new X509Certificate2(testData.ExternalCertificateBytes))
                {
                    // Assert.NoThrow
                    signedCms.CheckSignature(
                        new X509Certificate2Collection(signerCert),
                        true);
                }
            }

            ReadOnlySpan<byte> messageContentSpan = testData.MessageContent.Span;

            Assert.True(token.VerifyData(messageContentSpan), "token.VerifyData(correct)");
            Assert.False(token.VerifyData(messageContentSpan.Slice(1)), "token.VerifyData(incorrect)");

            byte[] messageHash = testData.HashBytes.ToArray();

            Assert.True(token.VerifyHash(messageHash), "token.VerifyHash(correct)");
            messageHash[0] ^= 0xFF;
            Assert.False(token.VerifyHash(messageHash), "token.VerifyHash(incorrect)");
        }

        [Fact]
        public static void TryParse_Fails_SignedCmsOfData()
        {
            Assert.False(
                Rfc3161TimestampToken.TryParse(
                    SignedDocuments.RsaPkcs1OneSignerIssuerAndSerialNumber,
                    out int bytesRead,
                    out Rfc3161TimestampToken token),
                "Rfc3161TimestampToken.TryParse");

            Assert.Equal(0, bytesRead);
            Assert.Null(token);
        }

        [Fact]
        public static void TryParse_Fails_Empty()
        {
            Assert.False(
                Rfc3161TimestampToken.TryParse(
                    ReadOnlyMemory<byte>.Empty,
                    out int bytesRead,
                    out Rfc3161TimestampToken token),
                "Rfc3161TimestampToken.TryParse");

            Assert.Equal(0, bytesRead);
            Assert.Null(token);
        }

        [Fact]
        public static void TryParse_Fails_EnvelopedCms()
        {
            byte[] encodedMessage =
            ("3082010c06092a864886f70d010703a081fe3081fb0201003181c83081c5020100302e301a311830160603550403130f5253"
             + "414b65795472616e7366657231021031d935fb63e8cfab48a0bf7b397b67c0300d06092a864886f70d010101050004818013"
             + "dc0eb2984a445d04a1f6246b8fe41f1d24507548d449d454d5bb5e0638d75ed101bf78c0155a5d208eb746755fbccbc86923"
             + "8443760a9ae94770d6373e0197be23a6a891f0c522ca96b3e8008bf23547474b7e24e7f32e8134df3862d84f4dea2470548e"
             + "c774dd74f149a56cdd966e141122900d00ad9d10ea1848541294a1302b06092a864886f70d010701301406082a864886f70d"
             + "030704089c8119f6cf6b174c8008bcea3a10d0737eb9").HexToByteArray();

            Assert.False(
                Rfc3161TimestampToken.TryParse(
                    encodedMessage,
                    out int bytesRead,
                    out Rfc3161TimestampToken token),
                "Rfc3161TimestampToken.TryParse");

            Assert.Equal(0, bytesRead);
            Assert.Null(token);
        }

        [Fact]
        public static void TryParse_Fails_MalformedToken()
        {
            ContentInfo contentInfo = new ContentInfo(
                new Oid(Oids.TstInfo, Oids.TstInfo),
                new byte[] { 1 });

            SignedCms cms = new SignedCms(contentInfo);

            using (X509Certificate2 cert = Certificates.RSAKeyTransferCapi1.TryGetCertificateWithPrivateKey())
            {
                cms.ComputeSignature(new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert));
            }

            Assert.False(
                Rfc3161TimestampToken.TryParse(
                    cms.Encode(),
                    out int bytesRead,
                    out Rfc3161TimestampToken token),
                "Rfc3161TimestampToken.TryParse");

            Assert.Equal(0, bytesRead);
            Assert.Null(token);
        }
    }
}
