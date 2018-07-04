// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests.Pkcs12
{
    public static class Pkcs12BuilderTests
    {
        private static readonly Oid s_zeroOid = new Oid("0.0", "0.0");
        private static readonly ReadOnlyMemory<byte> s_derNull = new byte[] { 0x05, 0x00 };

        private static readonly PbeParameters s_pbkdf2Parameters = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc,
            HashAlgorithmName.SHA384,
            0x1001);

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public static void EncryptDecryptMixBytesAndChars(bool encryptBytes)
        {
            Pkcs12SafeContents contents = new Pkcs12SafeContents();
            contents.AddSecret(s_zeroOid, s_derNull, skipCopy: true);

            string password = nameof(EncryptDecryptMixBytesAndChars);
            Span<byte> passwordUtf8Bytes = stackalloc byte[password.Length];
            Encoding.UTF8.GetBytes(password, passwordUtf8Bytes);

            Pkcs12Builder builder = new Pkcs12Builder();

            if (encryptBytes)
            {
                builder.AddSafeContentsEncrypted(contents, passwordUtf8Bytes, s_pbkdf2Parameters);
            }
            else
            {
                builder.AddSafeContentsEncrypted(contents, password, s_pbkdf2Parameters);
            }

            builder.SealAndMac(password, HashAlgorithmName.SHA1, 2048);

            byte[] encoded = builder.Encode();
            Pkcs12Info info = Pkcs12Info.Decode(encoded, out _, skipCopy: true);

            Assert.True(info.VerifyMac(password));
            ReadOnlyCollection<Pkcs12SafeContents> authSafe = info.AuthenticatedSafe;
            Assert.Equal(1, authSafe.Count);

            Pkcs12SafeContents readContents = authSafe[0];
            Assert.Equal(Pkcs12SafeContents.ConfidentialityMode.Password, readContents.DataConfidentialityMode);

            if (encryptBytes)
            {
                readContents.Decrypt(password);
            }
            else
            {
                readContents.Decrypt(passwordUtf8Bytes);
            }

            Assert.Equal(Pkcs12SafeContents.ConfidentialityMode.None, readContents.DataConfidentialityMode);

            List<Pkcs12SafeBag> bags = readContents.GetBags().ToList();
            Assert.Equal(1, bags.Count);
            SecretBag secretBag = Assert.IsType<SecretBag>(bags[0]);

            Assert.Equal(s_zeroOid.Value, secretBag.GetSecretType().Value);
            Assert.Equal(s_derNull.ByteArrayToHex(), secretBag.SecretValue.ByteArrayToHex());
        }
    }
}
