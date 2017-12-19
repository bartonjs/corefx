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

                // Assert.NoThrow
                signedCms.CheckSignature(
                    new X509Certificate2Collection(new X509Certificate2(testData.ExternalCertificateBytes)),
                    true);
            }

            Assert.True(false, "Test is finished being written");
        }
    }
}
