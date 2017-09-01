// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Text;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.EcDiffieHellman.Tests
{
    public partial class ECDiffieHellmanTests
    {
        private static ECDiffieHellmanCng NewDefaultECDHCng()
        {
            return new ECDiffieHellmanCng();
        }

        public static ECDiffieHellman OpenKnownKey()
        {
            byte[] blob = (
                "45434B36" +
                "42000000" +
                "014AACFCDA18F77EBF11DC0A2D394D3032E86C3AC0B5F558916361163EA6AD3DB27F6476D6C6E5D9C4A77BCCC5C0069D481718DACA3B1B13035AF5D246C4DC0CE0EA" +
                "00CA500F75537C782E027DE568F148334BF56F7E24C3830792236B5D20F7A33E99862B1744D2413E4C4AC29DBA42FC48D23AE5B916BED73997EC69B3911C686C5164" +
                "00202F9F5480723D1ACF15372CE0B99B6CC3E8772FFDDCF828EEEB314B3EAA35B19886AAB1E6871E548C261C7708BF561A4C373D3EED13F0749851F57B86DC049D71" +
                "").HexToByteArray();

            using (CngKey cngKey = CngKey.Import(blob, CngKeyBlobFormat.EccPrivateBlob))
            {
                return new ECDiffieHellmanCng(cngKey);
            }
        }

        [Fact]
        public static void ECCurve_ctor()
        {
            using (ECDiffieHellman ecdh = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP256))
            {
                Assert.Equal(256, ecdh.KeySize);
                ecdh.Exercise();
            }

            using (ECDiffieHellman ecdh = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP384))
            {
                Assert.Equal(384, ecdh.KeySize);
                ecdh.Exercise();
            }

            using (ECDiffieHellman ecdh = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP521))
            {
                Assert.Equal(521, ecdh.KeySize);
                ecdh.Exercise();
            }
        }

        [Fact]
        public static void CngKey_ReusesObject()
        {
            using (ECDiffieHellmanCng ecdh = NewDefaultECDHCng())
            {
                CngKey key1 = ecdh.Key;
                CngKey key2 = ecdh.Key;

                Assert.Same(key1, key2);
            }
        }

        public static IEnumerable<object[]> HashEquivalenceData()
        {
            return new object[][]
            {
                new object[] { HashAlgorithmName.SHA256, false, false },
                new object[] { HashAlgorithmName.SHA256, true, false },
                new object[] { HashAlgorithmName.SHA256, false, true },
                new object[] { HashAlgorithmName.SHA256, true, true },

                new object[] { HashAlgorithmName.SHA384, false, false },
                new object[] { HashAlgorithmName.SHA384, true, false },
                new object[] { HashAlgorithmName.SHA384, false, true },
                new object[] { HashAlgorithmName.SHA384, true, true },
            };
        }

        [Theory]
        [MemberData("HashEquivalenceData")]
        public static void Equivalence_Hash(HashAlgorithmName algorithm, bool prepend, bool append)
        {
            using (ECDiffieHellmanCng ecdh = NewDefaultECDHCng())
            using (ECDiffieHellmanPublicKey publicKey = ecdh.PublicKey)
            {
                byte[] secretPrepend = prepend ? new byte[3] : null;
                byte[] secretAppend = append ? new byte[4] : null;

                byte[] newWay = ecdh.DeriveKeyFromHash(publicKey, algorithm, secretPrepend, secretAppend);

                ecdh.HashAlgorithm = new CngAlgorithm(algorithm.Name);
                ecdh.SecretPrepend = secretPrepend;
                ecdh.SecretAppend = secretAppend;
                ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;

                byte[] oldWay = ecdh.DeriveKeyMaterial(publicKey);

                Assert.Equal(newWay, oldWay);
            }
        }

        public static IEnumerable<object[]> HmacEquivalenceData()
        {
            return new object[][]
            {
                new object[] { HashAlgorithmName.SHA256, false, false, false },
                new object[] { HashAlgorithmName.SHA256, true, false, false },
                new object[] { HashAlgorithmName.SHA256, false, false, true },
                new object[] { HashAlgorithmName.SHA256, true, false, true },
                new object[] { HashAlgorithmName.SHA256, false, true, false },
                new object[] { HashAlgorithmName.SHA256, true, true, false },
                new object[] { HashAlgorithmName.SHA256, false, true, true },
                new object[] { HashAlgorithmName.SHA256, true, true, true },

                new object[] { HashAlgorithmName.SHA384, false, false, false },
                new object[] { HashAlgorithmName.SHA384, true, false, false },
                new object[] { HashAlgorithmName.SHA384, false, false, true },
                new object[] { HashAlgorithmName.SHA384, true, false, true },
                new object[] { HashAlgorithmName.SHA384, false, true, false },
                new object[] { HashAlgorithmName.SHA384, true, true, false },
                new object[] { HashAlgorithmName.SHA384, false, true, true },
                new object[] { HashAlgorithmName.SHA384, true, true, true },
            };
        }

        [Theory]
        [MemberData("HmacEquivalenceData")]
        public static void Equivalence_Hmac(HashAlgorithmName algorithm, bool useSecretAgreementAsHmac, bool prepend, bool append)
        {
            using (ECDiffieHellmanCng ecdh = NewDefaultECDHCng())
            using (ECDiffieHellmanPublicKey publicKey = ecdh.PublicKey)
            {
                byte[] secretPrepend = prepend ? new byte[3] : null;
                byte[] secretAppend = append ? new byte[4] : null;
                byte[] hmacKey = useSecretAgreementAsHmac ? null : new byte[12];

                byte[] newWay = ecdh.DeriveKeyFromHmac(publicKey, algorithm, hmacKey, secretPrepend, secretAppend);

                ecdh.HashAlgorithm = new CngAlgorithm(algorithm.Name);
                ecdh.HmacKey = hmacKey;
                ecdh.SecretPrepend = secretPrepend;
                ecdh.SecretAppend = secretAppend;
                ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hmac;

                byte[] oldWay = ecdh.DeriveKeyMaterial(publicKey);

                Assert.Equal(newWay, oldWay);
            }
        }

        [Theory]
        [InlineData(4)]
        [InlineData(5)]
        public static void Equivalence_TlsPrf(int labelSize)
        {
            using (ECDiffieHellmanCng ecdh = NewDefaultECDHCng())
            using (ECDiffieHellmanPublicKey publicKey = ecdh.PublicKey)
            {
                byte[] label = new byte[labelSize];
                byte[] seed = new byte[64];

                byte[] newWay = ecdh.DeriveKeyTls(publicKey, label, seed);

                ecdh.Label = label;
                ecdh.Seed = seed;
                ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Tls;

                byte[] oldWay = ecdh.DeriveKeyMaterial(publicKey);

                Assert.Equal(newWay, oldWay);
            }
        }

        [Theory]
        [MemberData("HmacDerivationTestCases")]
        public static void HmacDerivation_KnownResults(
            HashAlgorithmName hashAlgorithm,
            string hmacKeyBytes,
            string prependBytes,
            string appendBytes,
            string answerBytes)
        {
            byte[] hmacKey = hmacKeyBytes == null ? null : hmacKeyBytes.HexToByteArray();
            byte[] prepend = prependBytes == null ? null : prependBytes.HexToByteArray();
            byte[] append = appendBytes == null ? null : appendBytes.HexToByteArray();
            byte[] answer = answerBytes.HexToByteArray();
            byte[] output;

            using (ECDiffieHellman ecdh = OpenKnownKey())
            using (ECDiffieHellmanPublicKey publicKey = ecdh.PublicKey)
            {
                output = ecdh.DeriveKeyFromHmac(publicKey, hashAlgorithm, hmacKey, prepend, append);
            }

            Assert.Equal(answer, output);
        }

        [Theory]
        [MemberData("TlsDerivationTestCases")]
        public static void TlsDerivation_KnownResults(string labelText, string answerBytes)
        {
            byte[] label = Encoding.ASCII.GetBytes(labelText);
            byte[] answer = answerBytes.HexToByteArray();
            byte[] output;

            using (ECDiffieHellman ecdh = OpenKnownKey())
            using (ECDiffieHellmanPublicKey publicKey = ecdh.PublicKey)
            {
                output = ecdh.DeriveKeyTls(publicKey, label, s_emptySeed);
            }

            Assert.Equal(answer, output);
        }

        [Theory]
        [MemberData("HashDerivationTestCases")]
        public static void HashDerivation_KnownResults(
            HashAlgorithmName hashAlgorithm,
            string prependBytes,
            string appendBytes,
            string answerBytes)
        {
            byte[] prepend = prependBytes == null ? null : prependBytes.HexToByteArray();
            byte[] append = appendBytes == null ? null : appendBytes.HexToByteArray();
            byte[] answer = answerBytes.HexToByteArray();
            byte[] output;

            using (ECDiffieHellman ecdh = OpenKnownKey())
            using (ECDiffieHellmanPublicKey publicKey = ecdh.PublicKey)
            {
                output = ecdh.DeriveKeyFromHash(publicKey, hashAlgorithm, prepend, append);
            }

            Assert.Equal(answer, output);
        }

        [Fact]
        public static void HashDerivation_AlgorithmsCreateECDH()
        {
            using (ECDiffieHellman ecdhCng = new ECDiffieHellmanCng())
            using (ECDiffieHellman ecdhAlgorithms = ECDiffieHellman.Create())
            {
                Assert.NotNull(ecdhAlgorithms.PublicKey);
                byte[] outputCng = ecdhCng.DeriveKeyMaterial(ecdhAlgorithms.PublicKey);
                byte[] outputAlgorithms = ecdhAlgorithms.DeriveKeyMaterial(ecdhCng.PublicKey);
                Assert.Equal(outputCng, outputAlgorithms);
            }
        }
    }
}