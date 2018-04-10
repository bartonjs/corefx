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

        private static void ReadWriteBase64PublicPkcs1(string base64PublicPkcs1, in RSAParameters expected)
        {
            byte[] derBytes = Convert.FromBase64String(base64PublicPkcs1);

            RSAParameters expectedPublic = new RSAParameters
            {
                Modulus = expected.Modulus,
                Exponent = expected.Exponent,
            };

            RSAParameters actual = RSAParameters.FromPkcs1PublicKey(derBytes, out int bytesRead);
            Assert.Equal(derBytes.Length, bytesRead);
            Assert.Null(actual.D);

            ImportExport.AssertKeyEquals(expectedPublic, actual);

            // This writes the public key portion from a private key parameter-set.
            byte[] output = expected.ToPkcs1PublicKey();
            Assert.Equal(derBytes, output);

            byte[] output2 = new byte[output.Length + 12];

            int bytesWritten = 3;

            Assert.False(actual.TryWritePkcs1PublicKey(output2.AsSpan(0, output.Length - 1), out bytesWritten));
            Assert.Equal(0, bytesWritten);
            Assert.Equal(0, output2[0]);

            string hexOutput = derBytes.ByteArrayToHex();

            Assert.True(actual.TryWritePkcs1PublicKey(output2, out bytesWritten));
            Assert.Equal(bytesRead, bytesWritten);
            Assert.Equal(hexOutput, output2.AsSpan(0, bytesWritten).ByteArrayToHex());
            Assert.Equal(0, output2[bytesWritten]);
            bytesWritten = 5;

            output2.AsSpan().Clear();
            Assert.True(actual.TryWritePkcs1PublicKey(output2.AsSpan(1, bytesRead), out bytesWritten));
            Assert.Equal(bytesRead, bytesWritten);
            Assert.Equal(hexOutput, output2.AsSpan(1, bytesWritten).ByteArrayToHex());
            Assert.Equal(0, output2[0]);
            Assert.Equal(0, output2[bytesWritten + 1]);
        }

        private static void ReadWriteBase64PrivatePkcs1(string base64PrivatePkcs1, in RSAParameters expected)
        {
            byte[] derBytes = Convert.FromBase64String(base64PrivatePkcs1);

            RSAParameters actual = RSAParameters.FromPkcs1PrivateKey(derBytes, out int bytesRead);
            Assert.Equal(derBytes.Length, bytesRead);
            Assert.NotNull(actual.D);

            ImportExport.AssertKeyEquals(expected, actual);

            byte[] output = expected.ToPkcs1PrivateKey();
            Assert.Equal(derBytes, output);

            byte[] output2 = new byte[output.Length + 12];

            int bytesWritten = 3;

            Assert.False(actual.TryWritePkcs1PrivateKey(output2.AsSpan(0, output.Length - 1), out bytesWritten));
            Assert.Equal(0, bytesWritten);
            Assert.Equal(0, output2[0]);

            string hexOutput = derBytes.ByteArrayToHex();

            Assert.True(actual.TryWritePkcs1PrivateKey(output2, out bytesWritten));
            Assert.Equal(bytesRead, bytesWritten);
            Assert.Equal(hexOutput, output2.AsSpan(0, bytesWritten).ByteArrayToHex());
            Assert.Equal(0, output2[bytesWritten]);
            bytesWritten = 5;

            output2.AsSpan().Clear();
            Assert.True(actual.TryWritePkcs1PrivateKey(output2.AsSpan(1, bytesRead), out bytesWritten));
            Assert.Equal(bytesRead, bytesWritten);
            Assert.Equal(hexOutput, output2.AsSpan(1, bytesWritten).ByteArrayToHex());
            Assert.Equal(0, output2[0]);
            Assert.Equal(0, output2[bytesWritten + 1]);
        }
    }
}
