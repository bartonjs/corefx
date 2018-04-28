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

            ReadOnlyCollection<Pkcs12SafeContents> authSafe = info.AuthenticatedSafe;
            Assert.Same(authSafe, info.AuthenticatedSafe);
            Assert.Equal(2, authSafe.Count);

            Assert.Equal(Pkcs12SafeContents.ConfidentialityMode.None, authSafe[0].DataConfidentialityMode);
            Assert.Equal(Pkcs12SafeContents.ConfidentialityMode.None, authSafe[1].DataConfidentialityMode);

            List<Pkcs12SafeBag> safe0Bags = new List<Pkcs12SafeBag>(authSafe[0]);

            Assert.Equal(1, safe0Bags.Count);
            Assert.IsType<ShroudedKeyBag>(safe0Bags[0]);

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
        }
    }
}
