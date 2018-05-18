// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
    internal static class Oids
    {
        internal const string RsaEncryption = "1.2.840.113549.1.1.1";

        // PKCS#5
        private const string Pkcs5Prefix = "1.2.840.113549.1.5.";
        internal const string PbeWithMD5AndDESCBC = Pkcs5Prefix + "3";
        internal const string PbeWithMD5AndRC2CBC = Pkcs5Prefix + "6";
        internal const string PbeWithSha1AndDESCBC = Pkcs5Prefix + "10";
        internal const string PbeWithSha1AndRC2CBC = Pkcs5Prefix + "11";
        internal const string Pbkdf2 = Pkcs5Prefix + "12";
        internal const string PasswordBasedEncryptionScheme2 = Pkcs5Prefix + "13";

        private const string RsaDsiDigestAlgorithmPrefix = "1.2.840.113549.2.";
        internal const string HmacWithSha1 = RsaDsiDigestAlgorithmPrefix + "7";
        internal const string HmacWithSha256 = RsaDsiDigestAlgorithmPrefix + "9";
        internal const string HmacWithSha384 = RsaDsiDigestAlgorithmPrefix + "10";
        internal const string HmacWithSha512 = RsaDsiDigestAlgorithmPrefix + "11";

        internal const string Rc2Cbc = "1.2.840.113549.3.2";
        internal const string TripleDesCbc = "1.2.840.113549.3.7";
        internal const string DesCbc = "1.3.14.3.2.7";
        internal const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
        internal const string Aes192Cbc = "2.16.840.1.101.3.4.1.22";
        internal const string Aes256Cbc = "2.16.840.1.101.3.4.1.42";

        internal const string EcPublicKey = "1.2.840.10045.2.1";
        internal const string EcDiffieHellman = "1.3.132.1.12";
        internal const string EcMQV = "1.3.132.1.13";

        internal const string secp256r1 = "1.2.840.10045.3.1.7";
        internal const string secp384r1 = "1.3.132.0.34";
        internal const string secp521r1 = "1.3.132.0.35";

        private const string Pkcs12Prefix = "1.2.840.113549.1.12.";
        private const string Pkcs12PbePrefix = Pkcs12Prefix + "1.";
        internal const string Pkcs12PbeWithShaAnd3Key3Des = Pkcs12PbePrefix + "3";
        internal const string Pkcs12PbeWithShaAnd2Key3Des= Pkcs12PbePrefix + "4";
        internal const string Pkcs12PbeWithShaAnd128BitRC2 = Pkcs12PbePrefix + "5";
        internal const string Pkcs12PbeWithShaAnd40BitRC2 = Pkcs12PbePrefix + "6";

        internal const string Dsa = "1.2.840.10040.4.1";
    }
}
