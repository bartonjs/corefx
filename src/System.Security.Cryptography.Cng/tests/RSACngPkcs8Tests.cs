// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Xunit;

namespace System.Security.Cryptography.Cng.Tests
{
    public static class RSACngPkcs8Tests
    {
        [Fact]
        public static void NoPlaintextExportFailsPkcs8()
        {
            using (RSACng rsa = new RSACng())
            {
                rsa.Key.SetExportPolicy(CngExportPolicies.AllowExport);

                Assert.ThrowsAny<CryptographicException>(
                    () => rsa.ExportPkcs8PrivateKey());

                Assert.ThrowsAny<CryptographicException>(
                    () => rsa.TryExportPkcs8PrivateKey(new byte[1], out _));
            }
        }

        [Theory]
        [InlineData(PbeEncryptionAlgorithm.Aes256Cbc)]
        [InlineData(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12)]
        public static void NoPlaintextExportAllowsEncryptedPkcs8(PbeEncryptionAlgorithm algorithm)
        {
            PbeParameters pbeParameters = new PbeParameters(
                algorithm,
                HashAlgorithmName.SHA1,
                2048);

            using (RSACng rsa = new RSACng())
            {
                rsa.Key.SetExportPolicy(CngExportPolicies.AllowExport);

                byte[] data = rsa.ExportEncryptedPkcs8PrivateKey(
                    nameof(NoPlaintextExportAllowsEncryptedPkcs8),
                    pbeParameters);

                Assert.False(
                    rsa.TryExportEncryptedPkcs8PrivateKey(
                        nameof(NoPlaintextExportAllowsEncryptedPkcs8),
                        pbeParameters,
                        data.AsSpan(0, data.Length - 1),
                        out int bytesWritten));

                Assert.Equal(0, bytesWritten);

                Assert.True(
                    rsa.TryExportEncryptedPkcs8PrivateKey(
                        nameof(NoPlaintextExportAllowsEncryptedPkcs8),
                        pbeParameters,
                        data.AsSpan(),
                        out bytesWritten));

                Assert.Equal(data.Length, bytesWritten);

                using (RSACng rsa2 = new RSACng())
                {
                    rsa2.ImportEncryptedPkcs8PrivateKey(
                        nameof(NoPlaintextExportAllowsEncryptedPkcs8),
                        data,
                        out int bytesRead);

                    Assert.Equal(data.Length, bytesRead);

                    HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
                    RSASignaturePadding signaturePadding = RSASignaturePadding.Pss;

                    byte[] signature = rsa2.SignData(
                        data,
                        hashAlgorithm,
                        signaturePadding);

                    Assert.True(
                        rsa.VerifyData(data, signature, hashAlgorithm, signaturePadding),
                        "Imported value has original private key");
                }
            }
        }

        internal static void SetExportPolicy(this CngKey key, CngExportPolicies policy)
        {
            key.SetProperty(
                new CngProperty(
                    "Export Policy",
                    BitConverter.GetBytes((int)policy),
                    CngPropertyOptions.Persist));
        }
    }
}
