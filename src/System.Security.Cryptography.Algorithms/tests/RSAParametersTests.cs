// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography.Rsa.Tests;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Algorithms.Tests
{
    public static class RSAParametersTests
    {
        [Fact]
        public static void ReadWriteBigExponentPrivatePkcs1()
        {
            ReadWriteBase64PrivatePkcs1(
                @"
MIIEpQIBAAKCAQEAr4HBy9ggP2JKU57WYIF1NyOTooN9SJDkihne02lzEVYglo1r
4NPao4qnd74C7gtrk7ck6NzBK2MrT6gLvJJbzmJPTKfMYGMGs5QD4oyTLSTdVG/+
TvajfxB3CyIV6oy7W/Qn6MTYm3nrM4N1EAxfg+Vd6bRGbd++7kJTmu8z7xh7d2DD
saGyEDwtgURWSgwQOaCchc9rWXTrUW/I1mI8lK46WguztMeSlX1DI5FWbPPipSr7
DBQrngaBuJcmca8rgt05Cjm5Oc9xlWhofkmQpjBQyndo3NazeIQvGP2x9tn/CWuv
e+uY3Pkw1m/P1QP1jUG/9GIS4k46/EXqQr2IRwIFAgAABEECggEAZK+bpSYkg9qS
tT8TQ5/Q7xMBL4eavAPLfAbxIJkE81LB8iNRncSL+u67URsNlV9hZ7UOA0/qKrxZ
C06p+/DFH5/+oW95J65oHL9zWEUryinVhwXgyqEGATsJpvX1kRSY0sT9aRVYVIjl
862Jg2yTyHda+rTRPCAUJmvo7muKpmyelC1JNGbI46Nw+OY3jOldY34DZzZwvkvK
zl/NrdI42fMso13oRXdqxL82EYgSMoxJP5HCWpvUJnLQr6/eCvfmGQeNSLSF75GT
Pdz/tUWHuPUS0iPIGJTpF4SYLzxcZYcTUfRlWrAjxK2ZtrA6lvkEbOEkpHHoKPBf
jbO8fMzy0QKBgQDkOjgmqXIErjzYZJqE20u/ByXEsI+MQ4QFV6DNBOMTr20EYN3m
nNxQitBD1yUU2npmvJGM2WJPSFZEud7qsr4OESlW1HLPD9UfgP0zhy0tzFYqBYiw
EujJDOfSVLlHksbnoCs8yqFQ5npkN3rMSUea1etVVJOyEAywQQlW99c79QKBgQDE
3S163WylB0DTlz9AxN69urUff1GBq65ybDJZaj7dCu5E2q3dipt6hkxP/a4AxMsf
EBd7oBwEZvgS1SJhD4xFQ/HD71efqeE66NoaSo2uMHhh0s6sA1YCebYbZRSYmIP+
hsXHQg0xKDj8L3C+1ZtSKWVCAYgmZM76OLSKNyPpywKBgAns8VH1zdLJ5uUmgjZP
pbTtCU9iLkAxv0a4UTWKWE3MtTKLC9m2NYkYP0kVk9KjrK0U4KrNofGBtcfZPFft
JuYsn8Jq835KBkTs6Cp7qK7Yj/HY6cVsxmOFzbJE6z1X0X5q1CCxnJ4r7hgZK4Fi
ZbdNpV+jgl+SLZ2Og1t2vzBxAoGBAImzO2lXiRdLiDaMSUY51NMmciRXKkCy/mGR
A4Qijj29Ee7ZBAzQOXfp4Nf8i/xL9Kkyg1Kf8dllkLGPTqvvAwN5Tyk+iNx2Gz4j
r+yxnyn4pNKpBYtxTPP00Qcz8T6nK78fvsjXHhBtDOIRXzrS3gIDJcOHmgkcQTzW
OX+Ds8uJAoGAfFftdMkXb7p2wjGDICUVBixmTU1J/z4DcEejCdoQ8VkM4Bt6HNGk
Mm3HWIPf+TEQqwZartFAybmBdqiBCAmt7HXoZ2SglRWX70Z/qP1QkYHNLkkeQ75B
CE5b4bVi7nbp+SyaseWurZ0pGmM35N6FveZ6DXK05Vrc8gf3paUiXhU=",
                TestData.RsaBigExponentParams);
        }

        [Fact]
        public static void ReadWriteDiminishedDPPrivatePkcs1()
        {
            ReadWriteBase64PrivatePkcs1(
                @"
MIIBOwIBAAJBALc/WfXui9VeJLf/AprRaoVDyW0lPlQxm5NTLEHDwUd7idstLzPX
uah0WEjgao5oO1BEUR4byjYlJ+F89Cs4BhUCAwEAAQJBAK/m8jYvnK9exaSR+DAh
Ij12ip5pB+HOFOdhCbS/coNoIowa6WJGrd3Np1m9BBhouWloF8UB6Iu8/e/wAg+F
9ykCIQDzcnsehnYgVZTTxzoCJ01PGpgESilRyFzNEsb8V60ZewIhAMCyOujqUqn7
Q079SlHzXuvocqIdt4IM1EmIlrlU9GGvAh8Ijv3FFPUSLfANgfOIH9mX7ldpzzGk
rmaUzxQvyuVLAiEArCTM8dSbopUADWnD4jArhU50UhWAIaM6ZrKqC8k0RKsCIQDC
yZWUxoxAdjfrBGsx+U6BHM0Myqqe7fY7hjWzj4aBCw==",
                TestData.DiminishedDPParameters);
        }

        [Fact]
        public static void ReadWritePublicPkcs1()
        {
            ReadWriteBase64PublicPkcs1(
                @"
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",
                TestData.RSA16384Params);
        }

        [Fact]
        public static void ReadWriteSubjectPublicKeyInfo()
        {
            ReadWriteBase64SubjectPublicKeyInfo(
                @"
MIIBJDANBgkqhkiG9w0BAQEFAAOCAREAMIIBDAKCAQEAr4HBy9ggP2JKU57WYIF1
NyOTooN9SJDkihne02lzEVYglo1r4NPao4qnd74C7gtrk7ck6NzBK2MrT6gLvJJb
zmJPTKfMYGMGs5QD4oyTLSTdVG/+TvajfxB3CyIV6oy7W/Qn6MTYm3nrM4N1EAxf
g+Vd6bRGbd++7kJTmu8z7xh7d2DDsaGyEDwtgURWSgwQOaCchc9rWXTrUW/I1mI8
lK46WguztMeSlX1DI5FWbPPipSr7DBQrngaBuJcmca8rgt05Cjm5Oc9xlWhofkmQ
pjBQyndo3NazeIQvGP2x9tn/CWuve+uY3Pkw1m/P1QP1jUG/9GIS4k46/EXqQr2I
RwIFAgAABEE=",
                TestData.RsaBigExponentParams);
        }

        [Fact]
        public static void ReadWrite16384Pkcs8()
        {
            ReadWriteBase64Pkcs8(
                @"
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
xBdaeIJFmTymL1LOru69mA9gwhuFFQ==",
                TestData.RSA16384Params);
        }

        [Fact]
        public static void ReadWriteDiminishedDPPkcs8()
        {
            ReadWriteBase64Pkcs8(
                @"
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAtz9Z9e6L1V4kt/8C
mtFqhUPJbSU+VDGbk1MsQcPBR3uJ2y0vM9e5qHRYSOBqjmg7UERRHhvKNiUn4Xz0
KzgGFQIDAQABAkEAr+byNi+cr17FpJH4MCEiPXaKnmkH4c4U52EJtL9yg2gijBrp
Ykat3c2nWb0EGGi5aWgXxQHoi7z97/ACD4X3KQIhAPNyex6GdiBVlNPHOgInTU8a
mARKKVHIXM0SxvxXrRl7AiEAwLI66OpSqftDTv1KUfNe6+hyoh23ggzUSYiWuVT0
Ya8CHwiO/cUU9RIt8A2B84gf2ZfuV2nPMaSuZpTPFC/K5UsCIQCsJMzx1JuilQAN
acPiMCuFTnRSFYAhozpmsqoLyTREqwIhAMLJlZTGjEB2N+sEazH5ToEczQzKqp7t
9juGNbOPhoEL",
                TestData.DiminishedDPParameters);
        }

        private static void ReadWriteBase64PublicPkcs1(
            string base64PublicPkcs1,
            in RSAParameters expected)
        {
            RSAParameters expectedPublic = new RSAParameters
            {
                Modulus = expected.Modulus,
                Exponent = expected.Exponent,
            };

            ReadWriteKey(
                base64PublicPkcs1,
                expectedPublic,
                RSAParameters.FromPkcs1PublicKey,
                p => p.ToPkcs1PublicKey(),
                (RSAParameters p, Span<byte> destination, out int bytesWritten) =>
                    p.TryWritePkcs1PublicKey(destination, out bytesWritten));
        }

        private static void ReadWriteBase64SubjectPublicKeyInfo(
            string base64SubjectPublicKeyInfo,
            in RSAParameters expected)
        {
            RSAParameters expectedPublic = new RSAParameters
            {
                Modulus = expected.Modulus,
                Exponent = expected.Exponent,
            };

            ReadWriteKey(
                base64SubjectPublicKeyInfo,
                expectedPublic,
                RSAParameters.FromSubjectPublicKeyInfo,
                p => p.ToSubjectPublicKeyInfo(),
                (RSAParameters p, Span<byte> destination, out int bytesWritten) =>
                    p.TryWriteSubjectPublicKeyInfo(destination, out bytesWritten));
        }

        private static void ReadWriteBase64PrivatePkcs1(
            string base64PrivatePkcs1,
            in RSAParameters expected)
        {
            ReadWriteKey(
                base64PrivatePkcs1,
                expected,
                RSAParameters.FromPkcs1PrivateKey,
                p => p.ToPkcs1PrivateKey(),
                (RSAParameters p, Span<byte> destination, out int bytesWritten) =>
                    p.TryWritePkcs1PrivateKey(destination, out bytesWritten));
        }

        private static void ReadWriteBase64Pkcs8(string base64Pkcs8, in RSAParameters expected)
        {
            ReadWriteKey(
                base64Pkcs8,
                expected,
                RSAParameters.FromPkcs8PrivateKey,
                p => p.ToPkcs8PrivateKey(),
                (RSAParameters p, Span<byte> destination, out int bytesWritten) =>
                    p.TryWritePkcs8PrivateKey(destination, out bytesWritten));
        }

        private static void ReadWriteKey(
            string base64PrivatePkcs1,
            in RSAParameters expected,
            ReadKeyFunc readFunc,
            WriteKeyToArrayFunc writeArrayFunc,
            WriteKeyToSpanFunc writeSpanFunc)
        {
            byte[] derBytes = Convert.FromBase64String(base64PrivatePkcs1);

            RSAParameters actual = readFunc(derBytes, out int bytesRead);
            Assert.Equal(derBytes.Length, bytesRead);

            ImportExport.AssertKeyEquals(expected, actual);

            byte[] output = writeArrayFunc(expected);
            Assert.Equal(derBytes, output);

            byte[] output2 = new byte[output.Length + 12];
            output2.AsSpan().Fill(0xC3);
            int bytesWritten = 3;

            Assert.False(writeSpanFunc(actual, output2.AsSpan(0, output.Length - 1), out bytesWritten));
            Assert.Equal(0, bytesWritten);
            Assert.Equal(0xC3, output2[0]);

            string hexOutput = derBytes.ByteArrayToHex();

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

        private delegate RSAParameters ReadKeyFunc(ReadOnlySpan<byte> source, out int bytesRead);

        private delegate byte[] WriteKeyToArrayFunc(RSAParameters rsaParameters);

        private delegate bool WriteKeyToSpanFunc(
            RSAParameters rsaParameters,
            Span<byte> destination,
            out int bytesWritten);
    }
}
