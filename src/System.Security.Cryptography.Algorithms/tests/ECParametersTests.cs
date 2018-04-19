// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography.Tests;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Algorithms.Tests
{
    public static class ECParametersTests
    {
        private static readonly ECParameters NistP521Key1 = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP521,

            Q =
            {
                X = (
                    "00751F26324C73CEF5D45EBB32937E3060E351960A57594AD03EB1CA0C5EA747" +
                    "1213366BA991D24406717F86FDEFDE086E09B954A57DC0F5E9459756D60C2AAE" +
                    "6DE0").HexToByteArray(),

                Y = (
                    "01A8DDBB3F02C8C23524729F548B7E23325233EF67DD30752B924F297459E3C2" +
                    "E12AE8D8F4FE4454E3847C18B255CACEF59737B918E1DE40F95E9FFE4F57B791" +
                    "53A0").HexToByteArray(),
            },

            D = (
                "01A55F8785A5730BAEE1D6B3D301069F7FD64D8B04CCEA57EFD5961E68F33FAB" +
                "43545166CA6553CD38FF713D1289C698BD7D086B55E01B5BD5ED27E3630376B1" +
                "1666").HexToByteArray(),
        };

        [Fact]
        public static void WritePkcs8ForNamedCurveRaw()
        {
            ECParameters expected = NistP521Key1;

            byte[] pkcs8 = expected.ToPkcs8PrivateKey();
            ECParameters readBack = ECParameters.FromPkcs8PrivateKey(pkcs8, out _);
            EccTestBase.AssertEqual(expected, readBack);
        }

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

            ReadWriteBase64Pkcs8(base64, NistP521Key1);
        }

        [Fact]
        public static void ReadWriteNistP521SubjectPublicKeyInfo()
        {
            const string base64 = @"
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAdR8mMkxzzvXUXrsyk34wYONRlgpX
WUrQPrHKDF6nRxITNmupkdJEBnF/hv3v3ghuCblUpX3A9elFl1bWDCqubeABqN27
PwLIwjUkcp9Ui34jMlIz72fdMHUrkk8pdFnjwuEq6Nj0/kRU44R8GLJVys71lze5
GOHeQPlen/5PV7eRU6A=";

            ReadWriteBase64SubjectPublicKeyInfo(base64, NistP521Key1);
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

            byte[] derBytes = Convert.FromBase64String(base64);

            ECParameters ecParameters =
                ECParameters.FromEncryptedPkcs8PrivateKey("qwerty", derBytes, out int bytesRead);

            Assert.Equal(derBytes.Length, bytesRead);
            EccTestBase.AssertEqual(NistP521Key1, ecParameters);
        }

        [Fact]
        public static void WriteEncryptedPkcs8()
        {
            ECParameters generated;

            using (ECDsa ecdsa = ECDsa.Create())
            {
                generated = ecdsa.ExportParameters(true);
            }

            byte[] encryptedKey = generated.ToEncryptedPkcs8PrivateKey(
                nameof(WriteEncryptedPkcs8),
                HashAlgorithmName.SHA512,
                1048576,
                Pkcs8.EncryptionAlgorithm.Aes128Cbc);

            Assert.ThrowsAny<CryptographicException>(
                () => ECParameters.FromEncryptedPkcs8PrivateKey("wrong answer", encryptedKey, out _));

            ECParameters readBack = ECParameters.FromEncryptedPkcs8PrivateKey(
                System.Text.Encoding.UTF8.GetBytes(nameof(WriteEncryptedPkcs8)),
                encryptedKey,
                out int bytesRead);

            Assert.Equal(encryptedKey.Length, bytesRead);
            EccTestBase.AssertEqual(generated, readBack);
        }

        private static void ReadWriteBase64Pkcs8(string base64Pkcs8, in ECParameters expected)
        {
            ReadWriteKey(
                base64Pkcs8,
                expected,
                ECParameters.FromPkcs8PrivateKey,
                p => p.ToPkcs8PrivateKey(),
                (ECParameters p, Span<byte> destination, out int bytesWritten) =>
                    p.TryWritePkcs8PrivateKey(destination, out bytesWritten));
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
                ECParameters.FromSubjectPublicKeyInfo,
                p => p.ToSubjectPublicKeyInfo(),
                (ECParameters p, Span<byte> destination, out int bytesWritten) =>
                    p.TryWriteSubjectPublicKeyInfo(destination, out bytesWritten));
        }

        private static void ReadWriteKey(
            string base64PrivatePkcs1,
            in ECParameters expected,
            ReadKeyFunc readFunc,
            WriteKeyToArrayFunc writeArrayFunc,
            WriteKeyToSpanFunc writeSpanFunc)
        {
            byte[] derBytes = Convert.FromBase64String(base64PrivatePkcs1);

            ECParameters actual = readFunc(derBytes, out int bytesRead);
            Assert.Equal(derBytes.Length, bytesRead);

            EccTestBase.AssertEqual(expected, actual);

            byte[] output = writeArrayFunc(expected);

            // Don't just assume that the input bytes will match, because there are
            // optional values that might not be written in one or the other.
            // But our writes should be deterministic.
            ECParameters secondActual = readFunc(output, out bytesRead);
            Assert.Equal(output.Length, bytesRead);

            EccTestBase.AssertEqual(expected, secondActual);

            byte[] output2 = new byte[output.Length + 12];
            output2.AsSpan().Fill(0xC3);
            int bytesWritten = 3;

            Assert.False(writeSpanFunc(actual, output2.AsSpan(0, output.Length - 1), out bytesWritten));
            Assert.Equal(0, bytesWritten);
            Assert.Equal(0xC3, output2[0]);

            string hexOutput = output.ByteArrayToHex();

            Assert.True(writeSpanFunc(actual, output2, out bytesWritten));
            Assert.Equal(bytesRead, bytesWritten);
            Assert.Equal(hexOutput, output2.AsSpan(0, bytesWritten).ByteArrayToHex());
            Assert.Equal(0xC3, output2[bytesWritten]);
            bytesWritten = 5;

            output2.AsSpan().Fill(0xC4);
            Assert.True(writeSpanFunc(actual, output2.AsSpan(1, bytesRead), out bytesWritten));
            Assert.Equal(bytesRead, bytesWritten);
            Assert.Equal(hexOutput, output2.AsSpan(1, bytesWritten).ByteArrayToHex());
            Assert.Equal(0xC4, output2[0]);
            Assert.Equal(0xC4, output2[bytesWritten + 1]);
        }

        private delegate ECParameters ReadKeyFunc(ReadOnlySpan<byte> source, out int bytesRead);

        private delegate byte[] WriteKeyToArrayFunc(ECParameters rsaParameters);

        private delegate bool WriteKeyToSpanFunc(
            ECParameters rsaParameters,
            Span<byte> destination,
            out int bytesWritten);
    }
}
