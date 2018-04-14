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

        public const string Rc2Cbc = "1.2.840.113549.3.2";
        public const string TripleDesCbc = "1.2.840.113549.3.7";
        public const string DesCbc = "1.3.14.3.2.7";
        public const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
        public const string Aes192Cbc = "2.16.840.1.101.3.4.1.22";
        public const string Aes256Cbc = "2.16.840.1.101.3.4.1.42";
    }
}
