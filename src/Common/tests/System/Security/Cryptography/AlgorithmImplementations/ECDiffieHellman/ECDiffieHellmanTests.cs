// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.Tests;
using System.Security.Cryptography;

using Xunit;

namespace System.Security.Cryptography.EcDiffieHellman.Tests
{
    public partial class ECDiffieHellmanTests : EccTests
    {
        private static List<object[]> s_everyKeysize;
        private static List<object[]> s_mismatchedKeysizes;

        private static ECDiffieHellman OpenKnownKey()
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

        public static IEnumerable<object[]> EveryKeysize()
        {
            if (s_everyKeysize == null)
            {
                List<object[]> everyKeysize = new List<object[]>();

                using (ECDiffieHellman defaultKeysize = ECDiffieHellmanFactory.Create())
                {
                    foreach (KeySizes keySizes in defaultKeysize.LegalKeySizes)
                    {
                        for (int size = keySizes.MinSize; size <= keySizes.MaxSize; size += keySizes.SkipSize)
                        {
                            everyKeysize.Add(new object[] { size });

                            if (keySizes.SkipSize == 0)
                            {
                                break;
                            }
                        }
                    }
                }

                s_everyKeysize = everyKeysize;
            }

            return s_everyKeysize;
        }

        public static IEnumerable<object[]> MismatchedKeysizes()
        {
            if (s_mismatchedKeysizes == null)
            {
                int firstSize = -1;
                List<object[]> mismatchedKeysizes = new List<object[]>();

                using (ECDiffieHellman defaultKeysize = ECDiffieHellmanFactory.Create())
                {
                    foreach (KeySizes keySizes in defaultKeysize.LegalKeySizes)
                    {
                        for (int size = keySizes.MinSize; size <= keySizes.MaxSize; size += keySizes.SkipSize)
                        {
                            if (firstSize == -1)
                            {
                                firstSize = size;
                            }
                            else if (size != firstSize)
                            {
                                mismatchedKeysizes.Add(new object[] { firstSize, size });
                            }

                            if (keySizes.SkipSize == 0)
                            {
                                break;
                            }
                        }
                    }
                }

                s_mismatchedKeysizes = mismatchedKeysizes;
            }

            return s_mismatchedKeysizes;
        }

        [Theory]
        [MemberData("EveryKeysize")]
        public static void SupportsKeysize(int keySize)
        {
            using (ECDiffieHellman ecdh = ECDiffieHellmanFactory.Create(keySize))
            {
                Assert.Equal(keySize, ecdh.KeySize);
            }
        }

        [Theory]
        [MemberData("EveryKeysize")]
        public static void PublicKey_NotNull(int keySize)
        {
            using (ECDiffieHellman ecdh = ECDiffieHellmanFactory.Create(keySize))
            using (ECDiffieHellmanPublicKey ecdhPubKey = ecdh.PublicKey)
            {
                Assert.NotNull(ecdhPubKey);
            }
        }

        [Fact]
        public static void PublicKeyIsFactory()
        {
            using (ECDiffieHellman ecdh = ECDiffieHellmanFactory.Create())
            using (ECDiffieHellmanPublicKey publicKey1 = ecdh.PublicKey)
            using (ECDiffieHellmanPublicKey publicKey2 = ecdh.PublicKey)
            {
                Assert.NotSame(publicKey1, publicKey2);
            }
        }
    }

    internal static class EcdhTestExtensions
    {
        internal static void Exercise(this ECDiffieHellman e)
        {
            // Make a few calls on this to ensure we aren't broken due to bad/prematurely released handles.
            int keySize = e.KeySize;

            using (ECDiffieHellmanPublicKey publicKey = e.PublicKey)
            {
                byte[] negotiated = e.DeriveKeyFromHash(publicKey, HashAlgorithmName.SHA256);
                Assert.Equal(256 / 8, negotiated.Length);
            }
        }
    }
}