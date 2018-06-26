// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests.Pkcs12
{
    public static class CertBagTests
    {
        [Fact]
        public static void CertificateTypeRequired()
        {
            AssertExtensions.Throws<ArgumentNullException>(
                "certificateType",
                () => new CertBag(null, ReadOnlyMemory<byte>.Empty));
        }

        [Fact]
        public static void InvalidCertificateTypeVerifiedLate()
        {
            var certBag = new CertBag(new Oid(null, null), ReadOnlyMemory<byte>.Empty, true);
            Assert.Equal(Oids.CertBag, certBag.GetBagId().Value);
            Assert.ThrowsAny<CryptographicException>(() => certBag.Encode());
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public static void SkipCopyHonored(bool skipCopy)
        {
            byte[] data = new byte[1];
            var certBag = new CertBag(new Oid(Oids.Pkcs7Data, Oids.Pkcs7Data), data, skipCopy);
            ReadOnlyMemory<byte> dataProperty = certBag.EncodedCertificate;

            Assert.Equal(data.Length, dataProperty.Length);
            Assert.True(data.AsSpan().SequenceEqual(dataProperty.Span));
            bool areSame = dataProperty.Span.Overlaps(data);

            if (skipCopy)
            {
                Assert.True(areSame);
            }
            else
            {
                Assert.False(areSame);
            }
        }

        [Fact]
        public static void DataNotValidatedInCtor()
        {
            using (X509Certificate2 cert = Certificates.RSAKeyTransferCapi1.GetCertificate())
            {
                var certBag = new CertBag(
                    new Oid("1.2.840.113549.1.9.22.1"),
                    cert.RawData,
                    skipCopy: true);

                Assert.True(certBag.IsX509Certificate, "certBag.IsX509Certificate");
                Assert.ThrowsAny<CryptographicException>(() => certBag.GetCertificate());
            }
        }

        [Fact]
        public static void OidCtorPreservesFriendlyName()
        {
            Oid oid = new Oid(Oids.Pkcs7Data, "Hello");
            var certBag = new CertBag(oid, ReadOnlyMemory<byte>.Empty, true);
            Oid firstCall = certBag.GetCertificateType();
            Oid secondCall = certBag.GetCertificateType();

            Assert.NotSame(oid, firstCall);
            Assert.NotSame(oid, secondCall);
            Assert.NotSame(firstCall, secondCall);
            Assert.Equal(oid.Value, firstCall.Value);
            Assert.Equal(oid.Value, secondCall.Value);
            Assert.Equal("Hello", firstCall.FriendlyName);
            Assert.Equal("Hello", secondCall.FriendlyName);
        }

        [Theory]
        [InlineData(Oids.Pkcs7Data, false)]
        [InlineData("1.2.840.113549.1.9.22.1", true)]
        [InlineData("1.2.840.113549.1.9.22.2", false)]
        [InlineData("1.2.840.113549.1.9.22.11", false)]
        public static void VerifyIsX509(string oidValue, bool expectedValue)
        {
            var certBag = new CertBag(new Oid(oidValue), ReadOnlyMemory<byte>.Empty, true);

            if (expectedValue)
            {
                Assert.True(certBag.IsX509Certificate, "certBag.IsX509Certificate");
                Assert.ThrowsAny<CryptographicException>(() => certBag.GetCertificate());
            }
            else
            {
                Assert.False(certBag.IsX509Certificate, "certBag.IsX509Certificate");
                Assert.Throws<InvalidOperationException>(() => certBag.GetCertificate());
            }
        }

        [Fact]
        public static void CertificateReadsSuccessfully()
        {
            using (X509Certificate2 cert = Certificates.RSAKeyTransferCapi1.GetCertificate())
            {
                Pkcs12SafeContents contents = new Pkcs12SafeContents();
                CertBag certBag = contents.AddCertificate(cert);

                using (X509Certificate2 extracted = certBag.GetCertificate())
                {
                    Assert.True(extracted.RawData.AsSpan().SequenceEqual(cert.RawData));
                }
            }
        }
    }
}
