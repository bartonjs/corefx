using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;

namespace RedZoneTests
{
    public partial class ECDiffieHellmanCngTests
    {
        private static ECDiffieHellmanCng NewDefaultECDHCng()
        {
            return new ECDiffieHellmanCng();
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
    }
}