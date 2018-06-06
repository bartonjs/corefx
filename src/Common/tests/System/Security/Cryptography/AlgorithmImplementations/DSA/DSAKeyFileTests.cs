﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Text;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Dsa.Tests
{
    public static class DSAKeyFileTests
    {
        public static bool SupportsFips186_3 => DSAFactory.SupportsFips186_3;

        [Fact]
        public static void ReadWriteDsa512Pkcs8()
        {
            ReadWriteBase64Pkcs8(
                @"
MIHGAgEAMIGoBgcqhkjOOAQBMIGcAkEA1qi38cr3ppZNB2Y/xpHSL2q81Vw3rvWN
IHRnQNgv4U4UY2NifZGSUULc3uOEvgoeBO1b9fRxSG9NmG1CoufflQIVAPq19iXV
1eFkMKHvYw6+M4l8wiT5AkAIRMSQ5S71jgWQLGNtZNHV6yxggqDU87/RzgeOh7Q6
fve77OGaTv4qbZwinTYAg86p9yHzmwW6+XBS3vxnpYorBBYCFC49eoTIW2Z4Xh9v
55aYKyKwy5i8",
                DSATestData.Dsa512Parameters);
        }

        [Fact]
        public static void ReadWriteDsa512EncryptedPkcs8()
        {
            // pbeWithSHA1And40BitRC2-CBC (PKCS12-PBE)
            ReadBase64EncryptedPkcs8(
                @"
MIHxMBwGCiqGSIb3DQEMAQYwDgQIxVJI9zn2I3oCAggABIHQxWZ9CzDb28iUpwh7
jlX2JTurz7kbP8NkbyuRO1wmnjTDohFek9VSUt+UzmOnl1sQKBg8uqNXzyFsc3Mo
me0NEZj19O90HD2+ahdWvlMuPJajYiXHXe4r+EwojEa4/KlMOhIQkv/NGLeIOYsu
MmM8IXx9Qg7ztZTNebpceHg0hBrshzFPBvzMCOnErp2YtMixddnBbamIab8wYNPn
QBS1HTKE5J9N78nM1DL4L7kE7VlpOezedRpvl+B8pK69QY7DBg98FnUsYPZhD4a+
UCouQg==",
                "forty",
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes128Cbc,
                    HashAlgorithmName.SHA256,
                    123456), 
                DSATestData.Dsa512Parameters);
        }

        [Fact]
        public static void ReadWriteDsa576EncryptedPkcs8()
        {
            // pbeWithSHA1And128BitRC2-CBC (PKCS12-PBE)
            ReadBase64EncryptedPkcs8(
                @"
MIIBATAcBgoqhkiG9w0BDAEFMA4ECBh9UuBb/JhlAgIIAASB4GqfDHTQYRRbRbdn
HJT0o+FUPzleK0noTuW6LXQEaJZscvmKA3fE1HC53qbNemN90RSrwz1fFBaRzhII
VWC+E+2uaM/Qi64e0ZqKJ86kE4sIe1AiGPz4PtyBauUYsMUTCuwLnrRyhzYv5d4Q
1aSE3jTZlwsNYmIiWO/+XUVIvNKGxW+DJTVAaI/Zxldxu31BmRt8caIUlrBHcNRI
h/A6S/A3PvZuJ3hh4vwneBpk1eeJNuKvjJ5fBza/OQQaiNfef8ad0lJfpQF1i3kL
itsfZ16jNKxoJbAx3psVTGdzxnw8",
                "If I had a trillion dollars...",
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes128Cbc,
                    HashAlgorithmName.SHA256,
                    123456),
                DSATestData.Dsa576Parameters);
        }

        [Fact]
        public static void ReadWriteDsa1024EncryptedPkcs8()
        {
            // pbeWithSHA1AndDES-CBC (PBES1)
            ReadBase64EncryptedPkcs8(
                @"
MIIBcTAbBgkqhkiG9w0BBQowDgQIEibTj5fv8jUCAggABIIBUPDssHf/llBiWN/M
e3cyuqVHA89Zda1Myh/YcKmGWpQgflr2CKOrmsw7nin+9bWlZDYP795EEKSAkCZg
ABHwJlTI9BKMUiXQUW8AwM5zqBJb/P/JOG2bFNXsZHUYUNh9g7I5mBwdCAih4D+R
QT4YuclwLvQmTewyjLtDGiDF/mC+4kpyBePeO9kfkRUDHiwSNk/efN4ug1xQgwhu
2RXvjJaAYu3JVTp9Gp86suix1gRWMOg+pHCamtCjC4B+91q3LLMdseAoSHmy25/x
qE3Db1UI4anCCnyEj/jDA8R6hZTFDjxu6bG0Z66g7I2GBDEYaaB+8x0vtiyu5LXo
6UZ53SX6S+jfIqJoF5YME9zVMoO2kwS/EGvc64+epCGcee1Nx4SGgUcr5HJYz1P4
CU+l4wPQR0rRmYHIJJIvFh5OXk84pV0crsOrekw7tHeNU6DMzw==",
                "Password > cipher",
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes192Cbc,
                    HashAlgorithmName.SHA256,
                    123456),
                DSATestData.GetDSA1024Params());
        }

        [Fact]
        public static void ReadWriteDsa1024EncryptedPkcs8_PasswordBytes()
        {
            // pbeWithSHA1AndDES-CBC (PBES1)
            ReadBase64EncryptedPkcs8(
                @"
MIIBcTAbBgkqhkiG9w0BBQowDgQIEibTj5fv8jUCAggABIIBUPDssHf/llBiWN/M
e3cyuqVHA89Zda1Myh/YcKmGWpQgflr2CKOrmsw7nin+9bWlZDYP795EEKSAkCZg
ABHwJlTI9BKMUiXQUW8AwM5zqBJb/P/JOG2bFNXsZHUYUNh9g7I5mBwdCAih4D+R
QT4YuclwLvQmTewyjLtDGiDF/mC+4kpyBePeO9kfkRUDHiwSNk/efN4ug1xQgwhu
2RXvjJaAYu3JVTp9Gp86suix1gRWMOg+pHCamtCjC4B+91q3LLMdseAoSHmy25/x
qE3Db1UI4anCCnyEj/jDA8R6hZTFDjxu6bG0Z66g7I2GBDEYaaB+8x0vtiyu5LXo
6UZ53SX6S+jfIqJoF5YME9zVMoO2kwS/EGvc64+epCGcee1Nx4SGgUcr5HJYz1P4
CU+l4wPQR0rRmYHIJJIvFh5OXk84pV0crsOrekw7tHeNU6DMzw==",
                Encoding.UTF8.GetBytes("Password > cipher"),
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes192Cbc,
                    HashAlgorithmName.SHA256,
                    123456),
                DSATestData.GetDSA1024Params());
        }

        [ConditionalFact(nameof(SupportsFips186_3))]
        public static void ReadWriteDsa2048EncryptedPkcs8()
        {
            ReadBase64EncryptedPkcs8(
                @"
MIICkTAbBgkqhkiG9w0BBQMwDgQIiFvwvRtsR00CAggABIICcLdrPIpSA2oPwA7S
/SBV43oICErpXe3XIjXwWTCRD+xgzQ1IUxJRHau8kIqz+mYwmN4tG9QZp/kc1HYx
1b72PtNc/NaduA6eT3DNZO7SslpnXkXKdXhMRsyzwawI4QfPlTZsL7bUgn4/O/GQ
yN1gHns7AHk6HOO3fLujSSqrosLQOvHkgvsxLJhcBhGTKUZqwA6SFwvWsYKh7ML2
Rwx336Nlzf7wpd49l8meJyZReqJ8Fg4kIhhcJTDAhaxWEdIw1dolshz1FSyZIb75
dhNVrpHtp+fQbWZpMRLGB+6qmWHjfzrSdSRda898P9oLgXpKffXDuFFcW+opW3uV
QZ2kM2Xx6NzcvdP4Bp3NKQmaW6inaES/IJvOasJd1KLTKb5Q16kq/0hrRw2fhBoc
YxXkO34answHx3Oapx3tJ40fwxi0RjPdEY+qNpMlHLiZrV6/dK6jfo3i9MT7xbQE
XLVGx9Yqp2eHNLPKnHuEaeDmOkYhsjVgrVGhDydqrN+9R6K6LOgU2Gxo7M/vhQiL
TwE5xKbUF6u82nyjma7DR7P6YDDY/RNfGRBusiMn7xlJs7ssG3ZTa0BBwlh6C4Iw
ak2nknIOVBrzyh+FJhcKRyExSDUt39uz0h+HH2MHNBs3gJv/xmURDRmlhwcqF7ZA
EDVKgNkAxxCnPVjTUalttxCxTv7FC/vxfN7ulB2uKzicegsf6t/nS6i2dpJjUYDF
8SU3qholnkPCi+bN+pNLtHiTo6o/7dhUf+/Y0DclLakVTduuOBc0v5arTtOB1Qlc
/NbPGH1ELzGP6HO8JzNYWabsAuY4AYoXuaTa7F0ygo6t9FP90w==",
                "Chicken Cannon",
                new PbeParameters(
                    PbeEncryptionAlgorithm.TripleDes3KeyPkcs12,
                    HashAlgorithmName.SHA1,
                    0x0202),
                DSATestData.GetDSA2048Params());
        }

        [Fact]
        public static void ReadWriteDsa576SubjectPublicKeyInfo()
        {
            ReadWriteBase64SubjectPublicKeyInfo(
                @"
MIIBCjCBuQYHKoZIzjgEATCBrQJJAOIWcwa//Ya7YvQye3eLv6B7pCMj7FZ7EGuV
Y4gr3dbX8u5zYPKZiI3p9Aphx40L2EQu+pwyK4aK02ezlB1yt6MyyVTrFikTKwIV
AMzc7M9fCyyP4jji8G8iE38X+usbAkkArxfUBhMCB54zA0p3oFjdtLgyrLEUt7jS
065EUd/4XrjdddRHQhg2nUhbIgZQZAYESrTmQH/apaKeldSWTKVZ6BxvfPzahyZl
A0wAAkkAgVpUm2/QztrwRLALfP4TUZAtdyfW1/tzYAOk4cTNjfv0MeT/RzPz+pLH
ZfDP+UTj7VaoW3WVPrFpASSJhbtfiROY6rXjlkXn",
                DSATestData.Dsa576Parameters);
        }

        [Fact]
        public static void ReadWriteDsa1024SubjectPublicKeyInfo()
        {
            ReadWriteBase64SubjectPublicKeyInfo(
                @"
MIIBtjCCASsGByqGSM44BAEwggEeAoGBAMFtJsdNbBYneZwJGFSOVT/ljHiB2khG
Kcr2QxH0snz+9r2w8hIGsP/EmZov7VO0O57ikQxo2ixDaoAY9JOPZHI2n1ZH0AW8
yW4iWQzBXjzU6g0TL12lr2qqCAewzE7zQEr1QvRUaze91qR+ZBEwg325k5fIRWNd
fcNtBTfkqEsxAhUA2DwOy3NVHi/jDVH89CNsZRiDrdcCgYBrw2a2Y1VUXgmPH+kO
VGm1Z+Cfp52Bfys2e0XezUMBpZyB1pEfdpHTcOFaxpLAS8EYcsFxp/5lTpY9fdpX
Wp6YzgJvt9OTSiWGCBNKjsXtaaKu3IlAG2et3kJ/F+2uty169F2asdWeGxPU770X
x2QzAmfd41LCDgW4DbPBCf6LnAOBhAACgYBpC7N6kUXgXW57R8RXiYqu3XJQHJ0W
55sa11qHLPAXqpC7+5Dxs7f1wDyH5G6HJWZVJv00FXsm9Zah8Jl/WfPmXvxhWlUt
XnVpxf/EWT1aApkRDnHJfhIhpaA/6aaTWu3YjvCzsvedOpntdfe4cebq8mgNltV0
pfTBO6zjtLRN4Q==",
                DSATestData.GetDSA1024Params());
        }

        [ConditionalFact(nameof(SupportsFips186_3))]
        public static void ReadWriteDsa2048SubjectPublicKeyInfo()
        {
            ReadWriteBase64SubjectPublicKeyInfo(
                @"
MIIDRjCCAjkGByqGSM44BAEwggIsAoIBAQCvj7mysUfJbzkjYGOb2qZUT/LNCGtg
SjMk9IVZXwLOrzLS1J8t062fU4TdCdAxgtuPCqBs4KD8ojZqWwMb0OL615e63IdK
DGeBUpwB4NaXBLQ983GuSps92B6wP12uKDeAESVoZjN7c6gk9+isphmBp8Z2STY9
LX0SzCMFMI0IS+xozDsbPvV3BTpeI0Sfujw+tvjNjqafEWs3SL0jf5f09+kRxBw5
TW99LVO3Z2GPDe1I571/MMZWiUgmSlTADTWKdumCbteRxrbL+MKcJFFzsdjSGUOO
WTc851VO9Jx4QKjFXOLl4sM8EKrY2Q8ox8su8UrV7YxOaZK0Hs7GUoj1AiEAyTqy
KSNygpl/I1QaOZu/dc7NML4L6VksBwQ+0wIh6ssCggEARKfSLeuinOGdZ40twR8R
i6oQ476pTeKcPsNsEKtNaIAEobf0OH/BzJYT5oUf7bvVRTGe3lRLlOT66cEGnnc0
+eavyKC4QGls3/4obhrxrW45Yp0MjGAWrGJfEAus9f90sjJcnZmm2LAxCyaPY+Nf
XRyNpmP5SrqQJEzsz5qM5dtUebAG+RMeXqeCIqMuKhA8H+8WkpsVbjIwyVQpXNo+
X5H3G1Z/o7d0uELxKM0NND1UaNuQc0pngDXmXmohzHMB9PU+a2ZxioP/KFpv3onK
WuHRuWM6JaNKkm+dKAj5v3ldk2eH/0xyhrx/xKgq+psGyRJRCakjuvPjd1XxV0uv
tQOCAQUAAoIBAAEb2FmGosQTFf8BxVSkXlqcRbOOvcwmYLbReIlgToAKb96OAXzt
N5P0pvuvu3YT/re6h4QavVmTXRiFiTnACm5GGbZWJHWVXW1yshNL7PWrNBGPYNhL
H/JodT8YjoYSVRMthMoKq2gbhVGHM5Txjg2u9rX5V37HyiqmMoG1Oa9YlCg+P7bc
xVN9ksi/58ByOsIS7vO3cY01w/3Zn3rgkSzHxHUhpW+lEb4xcS2XmuZ/F6e8xOWB
DqnKE43u09eCOe7vI5p3KULSPCgQwpciGVJWRhJ/nEuBYSwSrtwtyR6BFTsKIHwf
vAB5Wz646GeWztKawSR/9xIqHq8IECV1FXI=",
                DSATestData.GetDSA2048Params());
        }

        private static void ReadBase64EncryptedPkcs8(
            string base64EncPkcs8,
            string password,
            PbeParameters pbeParameters,
            in DSAParameters expected)
        {
            ReadWriteKey(
                base64EncPkcs8,
                expected,
                (DSA dsa, ReadOnlySpan<byte> source, out int read) =>
                    dsa.ImportEncryptedPkcs8PrivateKey(password, source, out read),
                dsa => dsa.ExportEncryptedPkcs8PrivateKey(password, pbeParameters),
                (DSA dsa, Span<byte> destination, out int written) =>
                    dsa.TryExportEncryptedPkcs8PrivateKey(password, pbeParameters, destination, out written),
                isEncrypted: true);
        }

        private static void ReadBase64EncryptedPkcs8(
            string base64EncPkcs8,
            byte[] passwordBytes,
            PbeParameters pbeParameters,
            in DSAParameters expected)
        {
            ReadWriteKey(
                base64EncPkcs8,
                expected,
                (DSA dsa, ReadOnlySpan<byte> source, out int read) =>
                    dsa.ImportEncryptedPkcs8PrivateKey(passwordBytes, source, out read),
                dsa => dsa.ExportEncryptedPkcs8PrivateKey(passwordBytes, pbeParameters),
                (DSA dsa, Span<byte> destination, out int written) =>
                    dsa.TryExportEncryptedPkcs8PrivateKey(passwordBytes, pbeParameters, destination, out written),
                isEncrypted: true);
        }

        private static void ReadWriteBase64SubjectPublicKeyInfo(
            string base64SubjectPublicKeyInfo,
            in DSAParameters expected)
        {
            DSAParameters expectedPublic = new DSAParameters
            {
                P = expected.P,
                G = expected.G,
                Q = expected.Q,
                Y = expected.Y,
            };

            ReadWriteKey(
                base64SubjectPublicKeyInfo,
                expectedPublic,
                (DSA dsa, ReadOnlySpan<byte> source, out int read) =>
                    dsa.ImportSubjectPublicKeyInfo(source, out read),
                dsa => dsa.ExportSubjectPublicKeyInfo(),
                (DSA dsa, Span<byte> destination, out int written) =>
                    dsa.TryExportSubjectPublicKeyInfo(destination, out written));
        }

        private static void ReadWriteBase64Pkcs8(string base64Pkcs8, in DSAParameters expected)
        {
            ReadWriteKey(
                base64Pkcs8,
                expected,
                (DSA dsa, ReadOnlySpan<byte> source, out int read) =>
                    dsa.ImportPkcs8PrivateKey(source, out read),
                dsa => dsa.ExportPkcs8PrivateKey(),
                (DSA dsa, Span<byte> destination, out int written) =>
                    dsa.TryExportPkcs8PrivateKey(destination, out written));
        }

        private static void ReadWriteKey(
            string base64,
            in DSAParameters expected,
            ReadKeyAction readAction,
            Func<DSA, byte[]> writeArrayFunc,
            WriteKeyToSpanFunc writeSpanFunc,
            bool isEncrypted = false)
        {
            bool isPrivateKey = expected.X != null;

            byte[] derBytes = Convert.FromBase64String(base64);
            byte[] arrayExport;
            byte[] tooBig;
            const int OverAllocate = 30;
            const int WriteShift = 6;

            using (DSA dsa = DSAFactory.Create())
            {
                readAction(dsa, derBytes, out int bytesRead);
                Assert.Equal(derBytes.Length, bytesRead);

                arrayExport = writeArrayFunc(dsa);

                DSAParameters dsaParameters = dsa.ExportParameters(isPrivateKey);
                DSAImportExport.AssertKeyEquals(expected, dsaParameters);
            }

            // Public key formats are stable.
            // Private key formats are not, since CNG recomputes the D value
            // and then all of the CRT parameters.
            if (!isPrivateKey)
            {
                Assert.Equal(derBytes.Length, arrayExport.Length);
                Assert.Equal(derBytes.ByteArrayToHex(), arrayExport.ByteArrayToHex());
            }

            using (DSA dsa = DSAFactory.Create())
            {
                Assert.ThrowsAny<CryptographicException>(
                    () => readAction(dsa, arrayExport.AsSpan(1), out _));

                Assert.ThrowsAny<CryptographicException>(
                    () => readAction(dsa, arrayExport.AsSpan(0, arrayExport.Length - 1), out _));

                readAction(dsa, arrayExport, out int bytesRead);
                Assert.Equal(arrayExport.Length, bytesRead);

                DSAParameters dsaParameters = dsa.ExportParameters(isPrivateKey);
                DSAImportExport.AssertKeyEquals(expected, dsaParameters);

                Assert.False(
                    writeSpanFunc(dsa, Span<byte>.Empty, out int bytesWritten),
                    "Write to empty span");

                Assert.Equal(0, bytesWritten);

                Assert.False(
                    writeSpanFunc(
                        dsa,
                        derBytes.AsSpan(0, Math.Min(derBytes.Length, arrayExport.Length) - 1),
                        out bytesWritten),
                    "Write to too-small span");

                Assert.Equal(0, bytesWritten);

                tooBig = new byte[arrayExport.Length + OverAllocate];
                tooBig.AsSpan().Fill(0xC4);

                Assert.True(writeSpanFunc(dsa, tooBig.AsSpan(WriteShift), out bytesWritten));
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

            using (DSA dsa = DSAFactory.Create())
            {
                readAction(dsa, tooBig.AsSpan(WriteShift), out int bytesRead);
                Assert.Equal(arrayExport.Length, bytesRead);

                arrayExport.AsSpan().Fill(0xCA);

                Assert.True(
                    writeSpanFunc(dsa, arrayExport, out int bytesWritten),
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

        private delegate void ReadKeyAction(DSA dsa, ReadOnlySpan<byte> source, out int bytesRead);
        private delegate bool WriteKeyToSpanFunc(DSA dsa, Span<byte> destination, out int bytesWritten);
    }
}
