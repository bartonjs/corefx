// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography.X509Certificates;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests.Pkcs12
{
    [PlatformSpecific(TestPlatforms.Windows)]
    public static class WriteToWindows
    {
        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(999)]
        [InlineData(1000)]
        [InlineData(1024)]
        [InlineData(2048)]
        [InlineData(10000)]
        [InlineData(123321)]
        public static void WriteEmpty(int iterationCount)
        {
            Pkcs12Builder builder = new Pkcs12Builder();
            string password = $"Password{iterationCount}IsMyVoice";

            // Windows 7 through 10-1709 only support SHA-1 as the MAC PRF
            builder.SealAndMac(password, HashAlgorithmName.SHA1, iterationCount);

            byte[] emptyPfx = builder.Encode();

            ImportedCollection coll =
                ImportedCollection.Import(emptyPfx, password, X509KeyStorageFlags.EphemeralKeySet);

            using (coll)
            {
                Assert.Equal(0, coll.Collection.Count);
            }
        }

        [Fact]
        public static void WriteOneCertNoKeys_NoEncryption()
        {
            Pkcs12SafeContents contents = new Pkcs12SafeContents();
            byte[] rawData;

            using (X509Certificate2 cert = Certificates.RSAKeyTransferCapi1.GetCertificate())
            {
                contents.AddCertificate(cert);
                rawData = cert.RawData;
            }

            Pkcs12Builder builder = new Pkcs12Builder();
            builder.AddSafeContentsUnencrypted(contents);

            const string password = nameof(WriteOneCertNoKeys_NoEncryption);
            builder.SealAndMac(password, HashAlgorithmName.SHA1, 1024);
            byte[] pfx = builder.Encode();

            Console.WriteLine(pfx.ByteArrayToHex());

            ImportedCollection coll =
                ImportedCollection.Import(pfx, password, X509KeyStorageFlags.EphemeralKeySet);

            using (coll)
            {
                Assert.Equal(1, coll.Collection.Count);
                Assert.Equal(rawData, coll.Collection[0].RawData);
                Assert.False(coll.Collection[0].HasPrivateKey, "coll.Collection[0].HasPrivateKey");
            }
        }

        [Fact]
        public static void WriteTwoCertsNoKeys_NoEncryption()
        {
            Pkcs12SafeContents contents = new Pkcs12SafeContents();
            byte[] rawData1;
            byte[] rawData2;

            using (X509Certificate2 cert1 = Certificates.RSAKeyTransferCapi1.GetCertificate())
            using (X509Certificate2 cert2 = Certificates.RSAKeyTransfer2.GetCertificate())
            {
                // Windows seems to treat these as a stack.  (LIFO)
                contents.AddCertificate(cert2);
                contents.AddCertificate(cert1);
                rawData1 = cert1.RawData;
                rawData2 = cert2.RawData;
            }

            Pkcs12Builder builder = new Pkcs12Builder();
            builder.AddSafeContentsUnencrypted(contents);

            const string password = nameof(WriteOneCertNoKeys_NoEncryption);
            builder.SealAndMac(password, HashAlgorithmName.SHA1, 1024);
            byte[] pfx = builder.Encode();

            Console.WriteLine(pfx.ByteArrayToHex());

            ImportedCollection coll =
                ImportedCollection.Import(pfx, password, X509KeyStorageFlags.EphemeralKeySet);

            using (coll)
            {
                Assert.Equal(2, coll.Collection.Count);
                Assert.Equal(rawData1, coll.Collection[0].RawData);
                Assert.Equal(rawData2, coll.Collection[1].RawData);
                Assert.False(coll.Collection[0].HasPrivateKey, "coll.Collection[0].HasPrivateKey");
                Assert.False(coll.Collection[1].HasPrivateKey, "coll.Collection[1].HasPrivateKey");
            }
        }
    }
}
