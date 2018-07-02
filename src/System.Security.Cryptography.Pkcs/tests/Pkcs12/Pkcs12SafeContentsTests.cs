// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests.Pkcs12
{
    public static class Pkcs12SafeContentsTests
    {
        private static readonly PbeParameters s_pbeParameters = new PbeParameters(
            PbeEncryptionAlgorithm.TripleDes3KeyPkcs12,
            HashAlgorithmName.SHA1,
            2048);

        [Fact]
        public static void StartsInReadWriteNoConfidentialityMode()
        {
            Pkcs12SafeContents contents = new Pkcs12SafeContents();
            Assert.Equal(Pkcs12SafeContents.ConfidentialityMode.None, contents.DataConfidentialityMode);
            Assert.False(contents.IsReadOnly);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public static void AddBagDisallowsNull(bool forReadOnly)
        {
            Pkcs12SafeContents contents = new Pkcs12SafeContents();

            if (forReadOnly)
            {
                contents = MakeReadonly(contents);
            }

            AssertExtensions.Throws<ArgumentNullException>(
                "safeBag",
                () => contents.AddSafeBag(null));
        }

        [Fact]
        public static void AddBagDisallowedInReadOnly()
        {
            Pkcs12SafeContents contents = MakeReadonly(new Pkcs12SafeContents());
            CertBag certBag = new CertBag(new Oid("0.0", "0.0"), new byte[] { 5, 0 });

            Assert.True(contents.IsReadOnly);
            Assert.Throws<InvalidOperationException>(() => contents.AddSafeBag(certBag));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public static void AddCertificateDisallowsNull(bool forReadOnly)
        {
            Pkcs12SafeContents contents = new Pkcs12SafeContents();

            if (forReadOnly)
            {
                contents = MakeReadonly(contents);
            }

            AssertExtensions.Throws<ArgumentNullException>(
                "certificate",
                () => contents.AddCertificate(null));
        }

        [Fact]
        public static void AddCertificateDisallowedInReadOnly()
        {
            Pkcs12SafeContents contents = MakeReadonly(new Pkcs12SafeContents());
            X509Certificate2 cert = new X509Certificate2();

            Assert.Throws<InvalidOperationException>(() => contents.AddCertificate(cert));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public static void AddShroudedKeyWithBytesDisallowsNull(bool forReadOnly)
        {
            Pkcs12SafeContents contents = new Pkcs12SafeContents();

            if (forReadOnly)
            {
                contents = MakeReadonly(contents);
            }

            AssertExtensions.Throws<ArgumentNullException>(
                "key",
                () => contents.AddShroudedKey(null, ReadOnlySpan<byte>.Empty, s_pbeParameters));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public static void AddShroudedKeyWithCharsDisallowsNull(bool forReadOnly)
        {
            Pkcs12SafeContents contents = new Pkcs12SafeContents();

            if (forReadOnly)
            {
                contents = MakeReadonly(contents);
            }

            AssertExtensions.Throws<ArgumentNullException>(
                "key",
                () => contents.AddShroudedKey(null, ReadOnlySpan<char>.Empty, s_pbeParameters));
        }

        [Fact]
        public static void AddShroudedKeyWithBytesDisallowedInReadOnly()
        {
            Pkcs12SafeContents contents = MakeReadonly(new Pkcs12SafeContents());

            using (RSA rsa = RSA.Create(512))
            {
                Assert.Throws<InvalidOperationException>(
                    () => contents.AddShroudedKey(rsa, ReadOnlySpan<byte>.Empty, s_pbeParameters));
            }
        }

        [Fact]
        public static void AddShroudedKeyWithCharsDisallowedInReadOnly()
        {
            Pkcs12SafeContents contents = MakeReadonly(new Pkcs12SafeContents());

            using (RSA rsa = RSA.Create(512))
            {
                Assert.Throws<InvalidOperationException>(
                    () => contents.AddShroudedKey(rsa, ReadOnlySpan<byte>.Empty, s_pbeParameters));
            }
        }

        private static Pkcs12SafeContents MakeReadonly(Pkcs12SafeContents contents)
        {
            Pkcs12Builder builder = new Pkcs12Builder();
            builder.AddSafeContentsUnencrypted(contents);
            builder.SealAndMac(ReadOnlySpan<char>.Empty, HashAlgorithmName.SHA1, 1);
            Pkcs12Info info = Pkcs12Info.Decode(builder.Encode(), out _, skipCopy: true);
            return info.AuthenticatedSafe.Single();
        }
    }
}
