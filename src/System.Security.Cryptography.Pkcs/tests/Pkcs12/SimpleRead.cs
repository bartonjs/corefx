// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests.Pkcs12
{
    public static class SimpleRead
    {
        [Fact]
        public static void Test1()
        {
            var loader = (CertLoaderFromRawData)Certificates.RSAKeyTransferCapi1;
            ReadOnlyMemory<byte> pfxData = loader.PfxData;

            Pkcs12Info info = Pkcs12Info.Decode(pfxData, out int bytesConsumed);
            Assert.Equal(pfxData.Length, bytesConsumed);

            Assert.Equal(Pkcs12Info.IntegrityMode.Password, info.DataIntegrityMode);

            Assert.True(info.VerifyMac(loader.Password), "VerifyMac (correct password)");
            Assert.False(info.VerifyMac(ReadOnlySpan<char>.Empty), "VerifyMac (empty password)");
            Assert.False(info.VerifyMac(loader.Password + loader.Password), "VerifyMac (doubled password)");
            Assert.False(info.VerifyMac(new string('a', 1048)), "VerifyMac (password > 1k)");

            ReadOnlyCollection<Pkcs12SafeContents> authSafe = info.AuthenticatedSafe;
            Assert.Same(authSafe, info.AuthenticatedSafe);
            Assert.Equal(2, authSafe.Count);

            Assert.Equal(Pkcs12SafeContents.ConfidentialityMode.None, authSafe[0].DataConfidentialityMode);
            Assert.Equal(Pkcs12SafeContents.ConfidentialityMode.None, authSafe[1].DataConfidentialityMode);

            List<Pkcs12SafeBag> safe0Bags = new List<Pkcs12SafeBag>(authSafe[0]);

            Assert.Equal(1, safe0Bags.Count);
            ShroudedKeyBag shroudedKeyBag = Assert.IsType<ShroudedKeyBag>(safe0Bags[0]);

            List<Pkcs12SafeBag> safe1Bags = new List<Pkcs12SafeBag>(authSafe[1]);

            Assert.Equal(1, safe0Bags.Count);
            Assert.IsType<CertBag>(safe1Bags[0]);
            CertBag certBag = (CertBag)safe1Bags[0];

            Assert.True(certBag.IsX509Certificate, "certBag.IsX509Certificate");
            Assert.InRange(certBag.RawData.Length, loader.CerData.Length + 2, int.MaxValue);

            using (X509Certificate2 fromLoader = loader.GetCertificate())
            using (X509Certificate2 fromBag = certBag.GetCertificate())
            {
                Assert.Equal(fromLoader.RawData, fromBag.RawData);
            }

            RSAParameters rsaParams = RSAParameters.FromEncryptedPkcs8PrivateKey(
                loader.Password,
                shroudedKeyBag.EncryptedPkcs8PrivateKey.Span,
                out int bytesRead);

            Assert.Equal(shroudedKeyBag.EncryptedPkcs8PrivateKey.Length, bytesRead);
            Assert.Equal("010001", rsaParams.Exponent.ByteArrayToHex());

            const string expectedDValue =
                "2A3F837316016A200D379F5B9ABCD5EB353F5A4D0A420758BA71AF2B91CA1C4B" +
                "33D16DB8D8B23900D67255497CB1B1A7CB061CF5FC40DB8E184848071984EC3F" +
                "D25A98E7BE825320473D81604AD38D4D642EB30876ABCC4775C47476560C8DCE" +
                "0DB45094AD7F8CF141FBF5AADE38A501F58665C970E97A68E596A603F43ADB61";

            Assert.Equal(expectedDValue, rsaParams.D.ByteArrayToHex());
        }
    }
}
