// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace Internal.Cryptography
{
    internal static class Oids
    {
        // Symmetric encryption algorithms
        public const string Rc2Cbc = "1.2.840.113549.3.2";
        public const string Rc4 = "1.2.840.113549.3.4";
        public const string TripleDesCbc = "1.2.840.113549.3.7";
        public const string DesCbc = "1.3.14.3.2.7";
        public const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
        public const string Aes192Cbc = "2.16.840.1.101.3.4.1.22";
        public const string Aes256Cbc = "2.16.840.1.101.3.4.1.42";

        // Asymmetric encryption algorithms
        public const string Rsa = "1.2.840.113549.1.1.1";
        public const string RsaOaep = "1.2.840.113549.1.1.7";
        public const string RsaPss = "1.2.840.113549.1.1.10";
        public const string Esdh = "1.2.840.113549.1.9.16.3.5";

        // Cryptographic Attribute Types
        public const string SigningTime = "1.2.840.113549.1.9.5";
        public const string ContentType = "1.2.840.113549.1.9.3";
        public const string DocumentDescription = "1.3.6.1.4.1.311.88.2.2";
        public const string MessageDigest = "1.2.840.113549.1.9.4";
        public const string CounterSigner = "1.2.840.113549.1.9.6";
        public const string SigningCertificate = "1.2.840.113549.1.9.16.2.12";
        public const string SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";
        public const string DocumentName = "1.3.6.1.4.1.311.88.2.1";

        // Key wrap algorithms
        public const string CmsRc2Wrap = "1.2.840.113549.1.9.16.3.7";
        public const string Cms3DesWrap = "1.2.840.113549.1.9.16.3.6";

        // PKCS7 Content Types.
        public const string Pkcs7Data = "1.2.840.113549.1.7.1";
        public const string Pkcs7Signed = "1.2.840.113549.1.7.2";
        public const string Pkcs7Enveloped = "1.2.840.113549.1.7.3";
        public const string Pkcs7SignedEnveloped = "1.2.840.113549.1.7.4";
        public const string Pkcs7Hashed = "1.2.840.113549.1.7.5";
        public const string Pkcs7Encrypted = "1.2.840.113549.1.7.6";

        public const string Md5 = "1.2.840.113549.2.5";
        public const string Sha1 = "1.3.14.3.2.26";
        public const string Sha256 = "2.16.840.1.101.3.4.2.1";
        public const string Sha384 = "2.16.840.1.101.3.4.2.2";
        public const string Sha512 = "2.16.840.1.101.3.4.2.3";

        // DSA CMS uses the combined signature+digest OID
        public const string DsaPublicKey = "1.2.840.10040.4.1";
        public const string DsaWithSha1 = "1.2.840.10040.4.3";
        public const string DsaWithSha256 = "2.16.840.1.101.3.4.3.2";
        public const string DsaWithSha384 = "2.16.840.1.101.3.4.3.3";
        public const string DsaWithSha512 = "2.16.840.1.101.3.4.3.4";

        // ECDSA CMS uses the combined signature+digest OID
        // https://tools.ietf.org/html/rfc5753#section-2.1.1
        public const string EcPublicKey = "1.2.840.10045.2.1";
        public const string ECDsaWithSha1 = "1.2.840.10045.4.1";
        public const string ECDsaWithSha256 = "1.2.840.10045.4.3.2";
        public const string ECDsaWithSha384 = "1.2.840.10045.4.3.3";
        public const string ECDsaWithSha512 = "1.2.840.10045.4.3.4";

        public const string Mgf1 = "1.2.840.113549.1.1.8";

        // Cert Extensions
        public const string SubjectKeyIdentifier = "2.5.29.14";
        public const string KeyUsage = "2.5.29.15";

        // RFC3161 Timestamping
        public const string TstInfo = "1.2.840.113549.1.9.16.1.4";
        public const string TimeStampingPurpose = "1.3.6.1.5.5.7.3.8";

        private const string Pkcs12Prefix = "1.2.840.113549.1.12.";
        private const string Pkcs12PbePrefix = Pkcs12Prefix + "1.";
        public const string Pkcs12PbeWithShaAnd3Key3Des = Pkcs12PbePrefix + "3";
        public const string Pkcs12PbeWithShaAnd2Key3Des = Pkcs12PbePrefix + "4";
        public const string Pkcs12PbeWithShaAnd128BitRC2 = Pkcs12PbePrefix + "5";
        public const string Pkcs12PbeWithShaAnd40BitRC2 = Pkcs12PbePrefix + "6";
        private const string Pkcs12BagTypesPrefix = Pkcs12Prefix + "10.1.";
        public const string Pkcs12KeyBag = Pkcs12BagTypesPrefix + "1";
        public const string Pkcs12ShroudedKeyBag = Pkcs12BagTypesPrefix + "2";
        public const string Pkcs12CertBag = Pkcs12BagTypesPrefix + "3";
        public const string Pkcs12CrlBag = Pkcs12BagTypesPrefix + "4";
        public const string Pkcs12SecretBag = Pkcs12BagTypesPrefix + "5";
        public const string Pkcs12SafeContentsBag = Pkcs12BagTypesPrefix + "6";
        public const string Pkcs12X509CertBagType = "1.2.840.113549.1.9.22.1";
        public const string Pkcs12SdsiCertBagType = "1.2.840.113549.1.9.22.1";

        // PKCS#5
        private const string Pkcs5Prefix = "1.2.840.113549.1.5.";
        public const string PbeWithMD5AndDESCBC = Pkcs5Prefix + "3";
        public const string PbeWithMD5AndRC2CBC = Pkcs5Prefix + "6";
        public const string PbeWithSha1AndDESCBC = Pkcs5Prefix + "10";
        public const string PbeWithSha1AndRC2CBC = Pkcs5Prefix + "11";
        public const string Pbkdf2 = Pkcs5Prefix + "12";
        public const string PasswordBasedEncryptionScheme2 = Pkcs5Prefix + "13";

        private const string RsaDsiDigestAlgorithmPrefix = "1.2.840.113549.2.";
        internal const string HmacWithSha1 = RsaDsiDigestAlgorithmPrefix + "7";
        internal const string HmacWithSha256 = RsaDsiDigestAlgorithmPrefix + "9";
        internal const string HmacWithSha384 = RsaDsiDigestAlgorithmPrefix + "10";
        internal const string HmacWithSha512 = RsaDsiDigestAlgorithmPrefix + "11";
    }
}
