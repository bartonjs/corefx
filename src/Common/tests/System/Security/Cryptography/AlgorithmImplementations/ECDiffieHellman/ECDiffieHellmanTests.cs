// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.Tests;
using System.Security.Cryptography;

using Xunit;
using Test.Cryptography;

namespace System.Security.Cryptography.EcDiffieHellman.Tests
{
    public partial class ECDiffieHellmanTests : EccTestBase
    {
        private static List<object[]> s_everyKeysize;
        private static List<object[]> s_mismatchedKeysizes;

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