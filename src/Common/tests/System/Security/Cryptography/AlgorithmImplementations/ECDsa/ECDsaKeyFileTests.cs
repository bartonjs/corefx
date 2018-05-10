// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography.Tests;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.EcDsa.Tests
{
    public static class ECDsaKeyFileTests
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

            ReadWriteBase64EncryptedPkcs8(
                base64,
                "qwerty",
                new PbeParameters(
                    PbeEncryptionAlgorithm.TripleDes3KeyPkcs12,
                    HashAlgorithmName.SHA1,
                    123321),
                NistP521Key1);
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
                (ECDsa ecdsa, ReadOnlyMemory<byte> source, out int read) =>
                    ecdsa.ImportEncryptedPkcs8PrivateKey(password, source, out read),
                ecdsa => ecdsa.ExportEncryptedPkcs8PrivateKey(password, pbe),
                (ECDsa ecdsa, Span<byte> destination, out int bytesWritten) =>
                    ecdsa.TryExportEncryptedPkcs8PrivateKey(password, pbe, destination, out bytesWritten),
                isEncrypted: true);
        }

        private static void ReadWriteBase64Pkcs8(string base64Pkcs8, in ECParameters expected)
        {
            ReadWriteKey(
                base64Pkcs8,
                expected,
                (ECDsa ecdsa, ReadOnlyMemory<byte> source, out int read) =>
                    ecdsa.ImportPkcs8PrivateKey(source, out read),
                ecdsa => ecdsa.ExportPkcs8PrivateKey(),
                (ECDsa ecdsa, Span<byte> destination, out int bytesWritten) =>
                    ecdsa.TryExportPkcs8PrivateKey(destination, out bytesWritten));
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
                (ECDsa ecdsa, ReadOnlyMemory<byte> source, out int read) => 
                    ecdsa.ImportSubjectPublicKeyInfo(source, out read),
                ecdsa => ecdsa.ExportSubjectPublicKeyInfo(),
                (ECDsa ecdsa, Span<byte> destination, out int written) =>
                    ecdsa.TryExportSubjectPublicKeyInfo(destination, out written));
        }

        private static void ReadWriteKey(
            string base64,
            in ECParameters expected,
            ReadKeyAction readAction,
            Func<ECDsa, byte[]> writeArrayFunc,
            WriteKeyToSpanFunc writeSpanFunc,
            bool isEncrypted = false)
        {
            bool isPrivateKey = expected.D != null;

            byte[] derBytes = Convert.FromBase64String(base64);
            byte[] arrayExport;
            byte[] tooBig;
            const int OverAllocate = 30;
            const int WriteShift = 6;

            using (ECDsa ecdsa = ECDsaFactory.Create())
            {
                readAction(ecdsa, derBytes, out int bytesRead);
                Assert.Equal(derBytes.Length, bytesRead);

                arrayExport = writeArrayFunc(ecdsa);

                ECParameters ecParameters = ecdsa.ExportParameters(isPrivateKey);
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

            using (ECDsa ecdsa = ECDsaFactory.Create())
            {
                Assert.ThrowsAny<CryptographicException>(
                    () => readAction(ecdsa, arrayExport.AsMemory(1), out _));

                Assert.ThrowsAny<CryptographicException>(
                    () => readAction(ecdsa, arrayExport.AsMemory(0, arrayExport.Length - 1), out _));

                readAction(ecdsa, arrayExport, out int bytesRead);
                Assert.Equal(arrayExport.Length, bytesRead);

                ECParameters ecParameters = ecdsa.ExportParameters(isPrivateKey);
                EccTestBase.AssertEqual(expected, ecParameters);

                Assert.False(
                    writeSpanFunc(ecdsa, Span<byte>.Empty, out int bytesWritten),
                    "Write to empty span");

                Assert.Equal(0, bytesWritten);

                Assert.False(
                    writeSpanFunc(
                        ecdsa,
                        derBytes.AsSpan(0, Math.Min(derBytes.Length, arrayExport.Length) - 1),
                        out bytesWritten),
                    "Write to too-small span");

                Assert.Equal(0, bytesWritten);

                tooBig = new byte[arrayExport.Length + OverAllocate];
                tooBig.AsSpan().Fill(0xC4);

                Assert.True(writeSpanFunc(ecdsa, tooBig.AsSpan(WriteShift), out bytesWritten));
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

            using (ECDsa ecdsa = ECDsaFactory.Create())
            {
                readAction(ecdsa, tooBig.AsMemory(WriteShift), out int bytesRead);
                Assert.Equal(arrayExport.Length, bytesRead);

                arrayExport.AsSpan().Fill(0xCA);

                Assert.True(
                    writeSpanFunc(ecdsa, arrayExport, out int bytesWritten),
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

        private delegate void ReadKeyAction(ECDsa ecdsa, ReadOnlyMemory<byte> source, out int bytesRead);
        private delegate bool WriteKeyToSpanFunc(ECDsa ecdsa, Span<byte> destination, out int bytesWritten);
    }
}
