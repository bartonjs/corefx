// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography.Tests;
using System.Text;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.EcDiffieHellman.Tests
{
    public static class ECDhKeyFileTests
    {
        [Fact]
        public static void ReadWriteNistP521Pkcs8()
        {
            const string base64 = @"
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBpV+HhaVzC67h1rPT
AQaff9ZNiwTM6lfv1ZYeaPM/q0NUUWbKZVPNOP9xPRKJxpi9fQhrVeAbW9XtJ+Nj
A3axFmahgYkDgYYABAB1HyYyTHPO9dReuzKTfjBg41GWCldZStA+scoMXqdHEhM2
a6mR0kQGcX+G/e/eCG4JuVSlfcD16UWXVtYMKq5t4AGo3bs/AsjCNSRyn1SLfiMy
UjPvZ90wdSuSTyl0WePC4Sro2PT+RFTjhHwYslXKzvWXN7kY4d5A+V6f/k9Xt5FT
oA==";

            ReadWriteBase64Pkcs8(base64, EccTestData.GetNistP521Key2());
        }

        [Fact]
        public static void ReadWriteNistP521SubjectPublicKeyInfo()
        {
            const string base64 = @"
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAdR8mMkxzzvXUXrsyk34wYONRlgpX
WUrQPrHKDF6nRxITNmupkdJEBnF/hv3v3ghuCblUpX3A9elFl1bWDCqubeABqN27
PwLIwjUkcp9Ui34jMlIz72fdMHUrkk8pdFnjwuEq6Nj0/kRU44R8GLJVys71lze5
GOHeQPlen/5PV7eRU6A=";

            ReadWriteBase64SubjectPublicKeyInfo(base64, EccTestData.GetNistP521Key2());
        }

        [Fact]
        public static void ReadNistP521EncryptedPkcs8_Pbes2_Aes128_Sha384()
        {
            // PBES2, PBKDF2 (SHA384), AES128
            const string base64 = @"
MIIBXTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI/JyXWyp/t3kCAggA
MAwGCCqGSIb3DQIKBQAwHQYJYIZIAWUDBAECBBA3H8mbFK5afB5GzIemCCQkBIIB
AKAz1z09ATUA8UfoDMwTyXiHUS8Mb/zkUCH+I7rav4orhAnSyYAyLKcHeGne+kUa
8ewQ5S7oMMLXE0HHQ8CpORlSgxTssqTAHigXEqdRb8nQ8hJJa2dFtNXyUeFtxZ7p
x+aSLD6Y3J+mgzeVp1ICgROtuRjA9RYjUdd/3cy2BAlW+Atfs/300Jhkke3H0Gqc
F71o65UNB+verEgN49rQK7FAFtoVI2oRjHLO1cGjxZkbWe2KLtgJWsgmexRq3/a+
Pfuapj3LAHALZtDNMZ+QCFN2ZXUSFNWiBSwnwCAtfFCn/EchPo3MFR3K0q/qXTua
qtlbnispri1a/EghiaPQ0po=";

            ReadWriteBase64EncryptedPkcs8(
                base64,
                "qwerty",
                new PbeParameters(
                    PbeEncryptionAlgorithm.TripleDes3KeyPkcs12,
                    HashAlgorithmName.SHA1,
                    12321),
                EccTestData.GetNistP521Key2());
        }

        [Fact]
        public static void ReadNistP521EncryptedPkcs8_Pbes2_Aes128_Sha384_PasswordBytes()
        {
            // PBES2, PBKDF2 (SHA384), AES128
            const string base64 = @"
MIIBXTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI/JyXWyp/t3kCAggA
MAwGCCqGSIb3DQIKBQAwHQYJYIZIAWUDBAECBBA3H8mbFK5afB5GzIemCCQkBIIB
AKAz1z09ATUA8UfoDMwTyXiHUS8Mb/zkUCH+I7rav4orhAnSyYAyLKcHeGne+kUa
8ewQ5S7oMMLXE0HHQ8CpORlSgxTssqTAHigXEqdRb8nQ8hJJa2dFtNXyUeFtxZ7p
x+aSLD6Y3J+mgzeVp1ICgROtuRjA9RYjUdd/3cy2BAlW+Atfs/300Jhkke3H0Gqc
F71o65UNB+verEgN49rQK7FAFtoVI2oRjHLO1cGjxZkbWe2KLtgJWsgmexRq3/a+
Pfuapj3LAHALZtDNMZ+QCFN2ZXUSFNWiBSwnwCAtfFCn/EchPo3MFR3K0q/qXTua
qtlbnispri1a/EghiaPQ0po=";

            ReadWriteBase64EncryptedPkcs8(
                base64,
                Encoding.UTF8.GetBytes("qwerty"),
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes192Cbc,
                    HashAlgorithmName.SHA1,
                    12321),
                EccTestData.GetNistP521Key2());
        }

        [Fact]
        public static void ReadNistP256EncryptedPkcs8_Pkcs12_3DES128_SHA1()
        {
            // PKCS12-PBE with 2-key 3DES and SHA1
            const string base64 = @"
MIGxMBwGCiqGSIb3DQEMAQQwDgQIlHjTmQQMiV8CAggABIGQpav+iaS2eMRXHtsJ
g720ICbxkZD7UWoAh/ONV/DptxequpV7lmi7ZS44kRIdtsVIFQlf/hTob4arbD1O
+IntWhLQDQ5FVszJtpmc3HIJ0cxe6bYbOr1aZuP0VxVBO2DjYUQi5lTC5NX7Kcu/
9DKRWrJJ4+0pA7pJAvxprhS49U9J9V3JAgOTOoJmw72p6oUI";

            ReadWriteBase64EncryptedPkcs8(
                base64,
                "2key",
                new PbeParameters(
                    PbeEncryptionAlgorithm.TripleDes3KeyPkcs12,
                    HashAlgorithmName.SHA1,
                    1024),
                EccTestData.GetNistP521ReferenceKey());
        }

        [Fact]
        public static void ReadWriteNistP256ECPrivateKey()
        {
            const string base64 = @"
MHcCAQEEIHChLC2xaEXtVv9oz8IaRys/BNfWhRv2NJ8tfVs0UrOKoAoGCCqGSM49
AwEHoUQDQgAEgQHs5HRkpurXDPaabivT2IaRoyYtIsuk92Ner/JmgKjYoSumHVmS
NfZ9nLTVjxeD08pD548KWrqmJAeZNsDDqQ==";

            ReadWriteBase64ECPrivateKey(
                base64,
                EccTestData.GetNistP521ReferenceKey());
        }

        private static void ReadWriteBase64EncryptedPkcs8(
            string base64EncryptedPkcs8,
            string password,
            PbeParameters pbe,
            in ECParameters expected)
        {
            ReadWriteKey(
                base64EncryptedPkcs8,
                expected,
                (ECDiffieHellman ecdh, ReadOnlySpan<byte> source, out int read) =>
                    ecdh.ImportEncryptedPkcs8PrivateKey(password, source, out read),
                ecdh => ecdh.ExportEncryptedPkcs8PrivateKey(password, pbe),
                (ECDiffieHellman ecdh, Span<byte> destination, out int bytesWritten) =>
                    ecdh.TryExportEncryptedPkcs8PrivateKey(password, pbe, destination, out bytesWritten),
                isEncrypted: true);
        }

        private static void ReadWriteBase64EncryptedPkcs8(
            string base64EncryptedPkcs8,
            byte[] passwordBytes,
            PbeParameters pbe,
            in ECParameters expected)
        {
            ReadWriteKey(
                base64EncryptedPkcs8,
                expected,
                (ECDiffieHellman ecdh, ReadOnlySpan<byte> source, out int read) =>
                    ecdh.ImportEncryptedPkcs8PrivateKey(passwordBytes, source, out read),
                ecdh => ecdh.ExportEncryptedPkcs8PrivateKey(passwordBytes, pbe),
                (ECDiffieHellman ecdh, Span<byte> destination, out int bytesWritten) =>
                    ecdh.TryExportEncryptedPkcs8PrivateKey(passwordBytes, pbe, destination, out bytesWritten),
                isEncrypted: true);
        }

        private static void ReadWriteBase64ECPrivateKey(string base64Pkcs8, in ECParameters expected)
        {
            ReadWriteKey(
                base64Pkcs8,
                expected,
                (ECDiffieHellman ecdh, ReadOnlySpan<byte> source, out int read) =>
                    ecdh.ImportECPrivateKey(source, out read),
                ecdh => ecdh.ExportECPrivateKey(),
                (ECDiffieHellman ecdh, Span<byte> destination, out int bytesWritten) =>
                    ecdh.TryExportECPrivateKey(destination, out bytesWritten));
        }

        private static void ReadWriteBase64Pkcs8(string base64Pkcs8, in ECParameters expected)
        {
            ReadWriteKey(
                base64Pkcs8,
                expected,
                (ECDiffieHellman ecdh, ReadOnlySpan<byte> source, out int read) =>
                    ecdh.ImportPkcs8PrivateKey(source, out read),
                ecdh => ecdh.ExportPkcs8PrivateKey(),
                (ECDiffieHellman ecdh, Span<byte> destination, out int bytesWritten) =>
                    ecdh.TryExportPkcs8PrivateKey(destination, out bytesWritten));
        }

        private static void ReadWriteBase64SubjectPublicKeyInfo(
            string base64SubjectPublicKeyInfo,
            in ECParameters expected)
        {
            ECParameters expectedPublic = expected;
            expectedPublic.D = null;

            ReadWriteKey(
                base64SubjectPublicKeyInfo,
                expectedPublic,
                (ECDiffieHellman ecdh, ReadOnlySpan<byte> source, out int read) => 
                    ecdh.ImportSubjectPublicKeyInfo(source, out read),
                ecdh => ecdh.ExportSubjectPublicKeyInfo(),
                (ECDiffieHellman ecdh, Span<byte> destination, out int written) =>
                    ecdh.TryExportSubjectPublicKeyInfo(destination, out written));
        }

        private static void ReadWriteKey(
            string base64,
            in ECParameters expected,
            ReadKeyAction readAction,
            Func<ECDiffieHellman, byte[]> writeArrayFunc,
            WriteKeyToSpanFunc writeSpanFunc,
            bool isEncrypted = false)
        {
            bool isPrivateKey = expected.D != null;

            byte[] derBytes = Convert.FromBase64String(base64);
            byte[] arrayExport;
            byte[] tooBig;
            const int OverAllocate = 30;
            const int WriteShift = 6;

            using (ECDiffieHellman ecdh = ECDiffieHellmanFactory.Create())
            {
                readAction(ecdh, derBytes, out int bytesRead);
                Assert.Equal(derBytes.Length, bytesRead);

                arrayExport = writeArrayFunc(ecdh);

                ECParameters ecParameters = ecdh.ExportParameters(isPrivateKey);
                EccTestBase.AssertEqual(expected, ecParameters);
            }

            // It's not reasonable to assume that arrayExport and derBytes have the same
            // contents, because the SubjectPublicKeyInfo and PrivateKeyInfo formats both
            // have the curve identifier in the AlgorithmIdentifier.Parameters field, and
            // either the input or the output may have chosen to then not emit it in the
            // optional domainParameters field of the ECPrivateKey blob.
            //
            // Once we have exported the data to normalize it, though, we should see
            // consistency in the answer format.

            using (ECDiffieHellman ecdh = ECDiffieHellmanFactory.Create())
            {
                Assert.ThrowsAny<CryptographicException>(
                    () => readAction(ecdh, arrayExport.AsSpan(1), out _));

                Assert.ThrowsAny<CryptographicException>(
                    () => readAction(ecdh, arrayExport.AsSpan(0, arrayExport.Length - 1), out _));

                readAction(ecdh, arrayExport, out int bytesRead);
                Assert.Equal(arrayExport.Length, bytesRead);

                ECParameters ecParameters = ecdh.ExportParameters(isPrivateKey);
                EccTestBase.AssertEqual(expected, ecParameters);

                Assert.False(
                    writeSpanFunc(ecdh, Span<byte>.Empty, out int bytesWritten),
                    "Write to empty span");

                Assert.Equal(0, bytesWritten);

                Assert.False(
                    writeSpanFunc(
                        ecdh,
                        derBytes.AsSpan(0, Math.Min(derBytes.Length, arrayExport.Length) - 1),
                        out bytesWritten),
                    "Write to too-small span");

                Assert.Equal(0, bytesWritten);

                tooBig = new byte[arrayExport.Length + OverAllocate];
                tooBig.AsSpan().Fill(0xC4);

                Assert.True(writeSpanFunc(ecdh, tooBig.AsSpan(WriteShift), out bytesWritten));
                Assert.Equal(arrayExport.Length, bytesWritten);

                Assert.Equal(0xC4, tooBig[WriteShift - 1]);
                Assert.Equal(0xC4, tooBig[WriteShift + bytesWritten + 1]);

                // If encrypted, the data should have had a random salt applied, so unstable.
                // Otherwise, we've normalized the data (even for private keys) so the output
                // should match what it output previously.
                if (isEncrypted)
                {
                    Assert.NotEqual(
                        arrayExport.ByteArrayToHex(),
                        tooBig.AsSpan(WriteShift, bytesWritten).ByteArrayToHex());
                }
                else
                {
                    Assert.Equal(
                        arrayExport.ByteArrayToHex(),
                        tooBig.AsSpan(WriteShift, bytesWritten).ByteArrayToHex());
                }
            }

            using (ECDiffieHellman ecdh = ECDiffieHellmanFactory.Create())
            {
                readAction(ecdh, tooBig.AsSpan(WriteShift), out int bytesRead);
                Assert.Equal(arrayExport.Length, bytesRead);

                arrayExport.AsSpan().Fill(0xCA);

                Assert.True(
                    writeSpanFunc(ecdh, arrayExport, out int bytesWritten),
                    "Write to precisely allocated Span");

                if (isEncrypted)
                {
                    Assert.NotEqual(
                        tooBig.AsSpan(WriteShift, bytesWritten).ByteArrayToHex(),
                        arrayExport.ByteArrayToHex());
                }
                else
                {
                    Assert.Equal(
                        tooBig.AsSpan(WriteShift, bytesWritten).ByteArrayToHex(),
                        arrayExport.ByteArrayToHex());
                }
            }
        }

        private delegate void ReadKeyAction(ECDiffieHellman ecdh, ReadOnlySpan<byte> source, out int bytesRead);
        private delegate bool WriteKeyToSpanFunc(ECDiffieHellman ecdh, Span<byte> destination, out int bytesWritten);
    }
}
