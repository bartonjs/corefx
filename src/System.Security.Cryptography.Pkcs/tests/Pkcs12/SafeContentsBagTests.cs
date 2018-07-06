// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Linq;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests.Pkcs12
{
    public static class SafeContentsBagTests
    {
        private static readonly Oid s_zeroOid = new Oid("0.0", "0.0");
        private static readonly ReadOnlyMemory<byte> s_derNull = new byte[] { 0x05, 0x00 };

        private static readonly PbeParameters s_win7Pbe = new PbeParameters(
            PbeEncryptionAlgorithm.TripleDes3KeyPkcs12,
            HashAlgorithmName.SHA1,
            2000);

        private static readonly PbeParameters s_pbkdf2Pbe = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc,
            HashAlgorithmName.SHA256,
            2000);

        [Fact]
        public static void CreateUnencryptedDisallowsNull()
        {
            AssertExtensions.Throws<ArgumentNullException>(
                "safeContents",
                () => SafeContentsBag.CreateUnencrypted(null));
        }

        [Fact]
        public static void CreateEncryptedWithBytesDisallowsNull()
        {
            AssertExtensions.Throws<ArgumentNullException>(
                "safeContents",
                () => SafeContentsBag.CreateEncrypted(null, ReadOnlySpan<byte>.Empty, s_pbkdf2Pbe));
        }

        [Fact]
        public static void CreateEncryptedWithCharsDisallowsNull()
        {
            AssertExtensions.Throws<ArgumentNullException>(
                "safeContents",
                () => SafeContentsBag.CreateEncrypted(null, ReadOnlySpan<char>.Empty, s_pbkdf2Pbe));
        }

        [Fact]
        public static void CreateUnencryptedSerializesInput()
        {
            CreateSerializesInput(
                contents => SafeContentsBag.CreateUnencrypted(contents),
                contents =>
                {
                    Assert.Equal(
                        Pkcs12SafeContents.ConfidentialityMode.None,
                        contents.DataConfidentialityMode);
                });
        }

        [Fact]
        public static void CreateEncryptedWithBytesSerializesInput()
        {
            byte[] key = { 1, 2, 3, 4, 5 };

            CreateSerializesInput(
                contents => SafeContentsBag.CreateEncrypted(contents, key, s_pbkdf2Pbe),
                contents =>
                {
                    Assert.Equal(
                        Pkcs12SafeContents.ConfidentialityMode.Password,
                        contents.DataConfidentialityMode);

                    contents.Decrypt(key);
                });
        }

        [Fact]
        public static void CreateEncryptedWithCharsSerializesInput()
        {
            char[] key = { 't', 'e', 's', 't' };

            CreateSerializesInput(
                contents => SafeContentsBag.CreateEncrypted(contents, key, s_pbkdf2Pbe),
                contents =>
                {
                    Assert.Equal(
                        Pkcs12SafeContents.ConfidentialityMode.Password,
                        contents.DataConfidentialityMode);

                    contents.Decrypt(key);
                });
        }

        private static void CreateSerializesInput(
            Func<Pkcs12SafeContents, SafeContentsBag> creator,
            Action<Pkcs12SafeContents> postprocessor)
        {
            Pkcs12SafeContents contents1 = new Pkcs12SafeContents();
            contents1.AddSecret(s_zeroOid, s_derNull);

            contents1.AddSecret(s_zeroOid, new byte[] { 4, 1, 2 }).Attributes.Add(
                new Pkcs9LocalKeyId(s_derNull.Span));

            contents1.AddSecret(s_zeroOid, new byte[] { 4, 1, 3 });

            SafeContentsBag safeContentsBag = creator(contents1);

            contents1.AddSecret(s_zeroOid, new byte[] { 4, 1, 4 });

            Pkcs12SafeContents contents2 = safeContentsBag.SafeContents;
            Assert.NotSame(contents2, contents1);

            postprocessor(contents2);

            List<Pkcs12SafeBag> bags1 = contents1.GetBags().ToList();
            List<Pkcs12SafeBag> bags2 = contents2.GetBags().ToList();

            Assert.Equal(4, bags1.Count);
            Assert.Equal(3, bags2.Count);

            for (int i = 0; i < bags2.Count; i++)
            {
                byte[] encoded1 = bags1[i].Encode();
                byte[] encoded2 = bags1[i].Encode();

                Assert.True(encoded1.AsSpan().SequenceEqual(encoded2), $"Bag {i} encodes the same");
            }
        }
    }
}
