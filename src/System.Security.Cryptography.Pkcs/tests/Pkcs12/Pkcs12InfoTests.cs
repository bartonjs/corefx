// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests.Pkcs12
{
    public static class Pkcs12InfoTests
    {
        [Fact]
        public static void ReadEmptyPfx()
        {
            Pkcs12Info info =
                Pkcs12Info.Decode(Pkcs12Documents.EmptyPfx, out int bytesRead, skipCopy: true);

            Assert.Equal(Pkcs12Documents.EmptyPfx.Length, bytesRead);
            Assert.Equal(Pkcs12Info.IntegrityMode.Password, info.DataIntegrityMode);

            Assert.False(info.VerifyMac("hello"), "Wrong password");
            Assert.True(info.VerifyMac(ReadOnlySpan<char>.Empty), "null password");
            Assert.False(info.VerifyMac(""), "empty password");
            Assert.False(info.VerifyMac("hello".AsSpan(5)), "sliced out");
            Assert.False(info.VerifyMac("hello".AsSpan(0, 0)), "zero-sliced");
            Assert.False(info.VerifyMac(new char[0]), "empty array");
            Assert.False(info.VerifyMac((new char[1]).AsSpan(1)), "sliced out array");
            Assert.False(info.VerifyMac((new char[1]).AsSpan(0, 0)), "zero-sliced array");

            ReadOnlyCollection<Pkcs12SafeContents> safes = info.AuthenticatedSafe;
            Assert.Equal(0, safes.Count);
        }

        [Fact]
        public static void ReadIndefiniteEncodingNoMac()
        {
            Pkcs12Info info = Pkcs12Info.Decode(
                Pkcs12Documents.IndefiniteEncodingNoMac,
                out int bytesRead,
                skipCopy: true);

            Assert.Equal(Pkcs12Documents.IndefiniteEncodingNoMac.Length, bytesRead);
            Assert.Equal(Pkcs12Info.IntegrityMode.None, info.DataIntegrityMode);

            ReadOnlyCollection<Pkcs12SafeContents> safes = info.AuthenticatedSafe;
            Assert.Equal(2, safes.Count);

            Pkcs12SafeContents firstSafe = safes[0];
            Pkcs12SafeContents secondSafe = safes[1];

            Assert.Equal(Pkcs12SafeContents.ConfidentialityMode.None, firstSafe.DataConfidentialityMode);
            Assert.Equal(Pkcs12SafeContents.ConfidentialityMode.None, secondSafe.DataConfidentialityMode);

            Assert.True(firstSafe.IsReadOnly, "firstSafe.IsReadOnly");
            Assert.True(secondSafe.IsReadOnly, "secondSafe.IsReadOnly");

            Pkcs12SafeBag[] firstContents = firstSafe.GetBags().ToArray();
            Pkcs12SafeBag[] secondContents = secondSafe.GetBags().ToArray();

            Assert.Equal(1, firstContents.Length);
            Assert.Equal(1, secondContents.Length);

            KeyBag keyBag = Assert.IsType<KeyBag>(firstContents[0]);
            CertBag certBag = Assert.IsType<CertBag>(secondContents[0]);

            CryptographicAttributeObjectCollection keyBagAttrs = keyBag.Attributes;
            CryptographicAttributeObjectCollection certBagAttrs = certBag.Attributes;

            Assert.Equal(2, keyBagAttrs.Count);
            Assert.Equal(2, certBagAttrs.Count);

            Assert.Equal(Oids.FriendlyName, keyBagAttrs[0].Oid.Value);
            Assert.Equal(1, keyBagAttrs[0].Values.Count);
            Assert.Equal(Oids.LocalKeyId, keyBagAttrs[1].Oid.Value);
            Assert.Equal(1, keyBagAttrs[1].Values.Count);

            Pkcs9AttributeObject keyFriendlyName =
                Assert.IsAssignableFrom<Pkcs9AttributeObject>(keyBagAttrs[0].Values[0]);

            Pkcs9LocalKeyId keyKeyId = Assert.IsType<Pkcs9LocalKeyId>(keyBagAttrs[1].Values[0]);

            Assert.Equal(Oids.FriendlyName, certBagAttrs[0].Oid.Value);
            Assert.Equal(1, certBagAttrs[0].Values.Count);
            Assert.Equal(Oids.LocalKeyId, certBagAttrs[1].Oid.Value);
            Assert.Equal(1, certBagAttrs[1].Values.Count);

            Pkcs9AttributeObject certFriendlyName =
                Assert.IsAssignableFrom<Pkcs9AttributeObject>(certBagAttrs[0].Values[0]);

            Pkcs9LocalKeyId certKeyId = Assert.IsType<Pkcs9LocalKeyId>(certBagAttrs[1].Values[0]);

            // This PFX gave a friendlyName value of "cert" to both the key and the cert.
            Assert.Equal("1E080063006500720074", keyFriendlyName.RawData.ByteArrayToHex());
            Assert.Equal(keyFriendlyName.RawData, certFriendlyName.RawData);

            // The private key (KeyBag) and the public key (CertBag) are matched from their keyId value.
            Assert.Equal("0414EDF3D122CF623CF0CFC9CD226261E8415A83E630", keyKeyId.RawData.ByteArrayToHex());
            Assert.Equal("EDF3D122CF623CF0CFC9CD226261E8415A83E630", keyKeyId.KeyId.ByteArrayToHex());
            Assert.Equal(keyKeyId.RawData, certKeyId.RawData);

            using (X509Certificate2 cert = certBag.GetCertificate())
            using (RSA privateKey = RSA.Create())
            using (RSA publicKey = cert.GetRSAPublicKey())
            {
                privateKey.ImportPkcs8PrivateKey(keyBag.Pkcs8PrivateKey.Span, out _);

                Assert.Equal(
                    publicKey.ExportSubjectPublicKeyInfo().ByteArrayToHex(),
                    privateKey.ExportSubjectPublicKeyInfo().ByteArrayToHex());
            }
        }
    }
}
