﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Security.Cryptography.Asn1;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Tests.Asn1
{
    public sealed class ReadUTF8String : Asn1ReaderTests
    {
        public static IEnumerable<object[]> ValidEncodingData { get; } =
            new object[][]
            {
                new object[]
                {
                    PublicEncodingRules.BER,
                    "0C0D4A6F686E20512E20536D697468",
                    "John Q. Smith",
                },
                new object[]
                {
                    PublicEncodingRules.CER,
                    "0C0D4A6F686E20512E20536D697468",
                    "John Q. Smith",
                },
                new object[]
                {
                    PublicEncodingRules.DER,
                    "0C0D4A6F686E20512E20536D697468",
                    "John Q. Smith",
                },
                new object[]
                {
                    PublicEncodingRules.BER,
                    "2C80" + "040D4A6F686E20512E20536D697468" + "0000",
                    "John Q. Smith",
                },
                new object[]
                {
                    PublicEncodingRules.BER,
                    "2C0F" + "040D4A6F686E20512E20536D697468",
                    "John Q. Smith",
                },
                new object[]
                {
                    PublicEncodingRules.BER,
                    "0C00",
                    "",
                },
                new object[]
                {
                    PublicEncodingRules.CER,
                    "0C00",
                    "",
                },
                new object[]
                {
                    PublicEncodingRules.DER,
                    "0C00",
                    "",
                },
                new object[]
                {
                    PublicEncodingRules.BER,
                    "2C00",
                    "",
                },
                new object[]
                {
                    PublicEncodingRules.BER,
                    "2C80" + "0000",
                    "",
                },
                new object[]
                {
                    PublicEncodingRules.BER,
                    "2C80" +
                      "2480" +
                        // "Dr."
                        "040344722E" +
                        // " & "
                        "0403202620" +
                        // "Mrs."
                        "04044D72732E" +
                        "0000" +
                      // " "
                      "040120" +
                      "2480" +
                        "240C" +
                          // "Smith"
                          "0405536D697468" +
                          // hyphen (U+2010)
                          "0403E28090" +
                        "0000" +
                      // "Jones"
                      "04054A6F6E6573" +
                      "2480" +
                        // " "
                        "040120" +
                        "2480" +
                          // The next three bytes are U+FE60, small ampersand
                          // Don't know why any system would break this one character
                          // into three primitives, but it should work.
                          "0401EF" +
                          "0401B9" +
                          "0401A0" +
                          "0000" +
                        // " "
                        "040120" +
                        // "children"
                        "04086368696C6472656E" +
                        "0000" +
                      "0000",
                    "Dr. & Mrs. Smith\u2010Jones \uFE60 children",
                },
            };

        [Theory]
        [MemberData(nameof(ValidEncodingData))]
        public static void TryCopyUTF8String(
            PublicEncodingRules ruleSet,
            string inputHex,
            string expectedValue)
        {
            byte[] inputData = inputHex.HexToByteArray();
            char[] output = new char[expectedValue.Length];

            AsnReader reader = new AsnReader(inputData);
            bool copied;
            int charsWritten;

            if (output.Length > 0)
            {
                output[0] = 'a';

                copied = reader.TryCopyUTF8String(
                    (AsnEncodingRules)ruleSet,
                    output.AsSpan().Slice(0, expectedValue.Length - 1),
                    out charsWritten);

                Assert.False(copied, "reader.TryCopyUTF8String - too short");
                Assert.Equal(0, charsWritten);
                Assert.Equal('a', output[0]);
            }

            copied = reader.TryCopyUTF8String(
                (AsnEncodingRules)ruleSet,
                output,
                out charsWritten);

            Assert.True(copied, "reader.TryCopyUTF8String");

            string actualValue = new string(output, 0, charsWritten);
            Assert.Equal(expectedValue, actualValue);
        }

        [Theory]
        [MemberData(nameof(ValidEncodingData))]
        public static void TryCopyUTF8StringBytes(
            PublicEncodingRules ruleSet,
            string inputHex,
            string expectedString)
        {
            byte[] inputData = inputHex.HexToByteArray();
            string expectedHex = Text.Encoding.UTF8.GetBytes(expectedString).ByteArrayToHex();
            byte[] output = new byte[expectedHex.Length / 2];

            AsnReader reader = new AsnReader(inputData);
            bool copied;
            int bytesWritten;

            if (output.Length > 0)
            {
                output[0] = 32;

                copied = reader.TryCopyUTF8StringBytes(
                    (AsnEncodingRules)ruleSet,
                    output.AsSpan().Slice(0, output.Length - 1),
                    out bytesWritten);

                Assert.False(copied, "reader.TryCopyUTF8StringBytes - too short");
                Assert.Equal(0, bytesWritten);
                Assert.Equal(32, output[0]);
            }

            copied = reader.TryCopyUTF8StringBytes(
                (AsnEncodingRules)ruleSet,
                output,
                out bytesWritten);

            Assert.True(copied, "reader.TryCopyUTF8StringBytes");

            Assert.Equal(
                expectedHex,
                new ReadOnlySpan<byte>(output, 0, bytesWritten).ByteArrayToHex());

            Assert.Equal(output.Length, bytesWritten);
        }

        [Theory]
        [InlineData(PublicEncodingRules.BER, "0C0120", true)]
        [InlineData(PublicEncodingRules.BER, "2C80" + "040120" + "0000", false)]
        [InlineData(PublicEncodingRules.BER, "2C03" + "040120", false)]
        public static void TryGetUTF8StringBytes(
            PublicEncodingRules ruleSet,
            string inputHex,
            bool expectSuccess)
        {
            byte[] inputData = inputHex.HexToByteArray();
            AsnReader reader = new AsnReader(inputData);

            bool got = reader.TryGetUTF8StringBytes(
                (AsnEncodingRules)ruleSet,
                out ReadOnlySpan<byte> contents);

            if (expectSuccess)
            {
                Assert.True(got, "reader.TryGetUTF8StringBytes");

                unsafe
                {
                    fixed (byte* inputPtr = &inputData[2])
                    fixed (byte* matchPtr = &contents.DangerousGetPinnableReference())
                    {
                        Assert.Equal((IntPtr)inputPtr, (IntPtr)matchPtr);
                    }
                }
            }
            else
            {
                Assert.False(got, "reader.TryGetUTF8StringBytes");
                Assert.True(contents.IsEmpty, "contents.IsEmpty");
            }
        }

        [Theory]
        [InlineData("Incomplete Tag", PublicEncodingRules.BER, "1F")]
        [InlineData("Incomplete Tag", PublicEncodingRules.CER, "1F")]
        [InlineData("Incomplete Tag", PublicEncodingRules.DER, "1F")]
        [InlineData("Missing Length", PublicEncodingRules.BER, "0C")]
        [InlineData("Missing Length", PublicEncodingRules.CER, "0C")]
        [InlineData("Missing Length", PublicEncodingRules.DER, "0C")]
        [InlineData("Missing Contents", PublicEncodingRules.BER, "0C01")]
        [InlineData("Missing Contents", PublicEncodingRules.CER, "0C01")]
        [InlineData("Missing Contents", PublicEncodingRules.DER, "0C01")]
        [InlineData("Length Too Long", PublicEncodingRules.BER, "0C034869")]
        [InlineData("Length Too Long", PublicEncodingRules.CER, "0C034869")]
        [InlineData("Length Too Long", PublicEncodingRules.DER, "0C034869")]
        [InlineData("Constructed Form", PublicEncodingRules.DER, "2C03040149")]
        public static void TryGetUTF8StringBytes_Throws(
            string description,
            PublicEncodingRules ruleSet,
            string inputHex)
        {
            byte[] inputData = inputHex.HexToByteArray();

            Assert.Throws<CryptographicException>(
                () =>
                {
                    AsnReader reader = new AsnReader(inputData);

                    reader.TryGetUTF8StringBytes(
                        (AsnEncodingRules)ruleSet,
                        out ReadOnlySpan<byte> contents);
                });
        }

        [Theory]
        [InlineData("Empty", PublicEncodingRules.BER, "")]
        [InlineData("Empty", PublicEncodingRules.CER, "")]
        [InlineData("Empty", PublicEncodingRules.DER, "")]
        [InlineData("Incomplete Tag", PublicEncodingRules.BER, "1F")]
        [InlineData("Incomplete Tag", PublicEncodingRules.CER, "1F")]
        [InlineData("Incomplete Tag", PublicEncodingRules.DER, "1F")]
        [InlineData("Missing Length", PublicEncodingRules.BER, "0C")]
        [InlineData("Missing Length", PublicEncodingRules.CER, "0C")]
        [InlineData("Missing Length", PublicEncodingRules.DER, "0C")]
        [InlineData("Missing Contents", PublicEncodingRules.BER, "0C01")]
        [InlineData("Missing Contents", PublicEncodingRules.CER, "0C01")]
        [InlineData("Missing Contents", PublicEncodingRules.DER, "0C01")]
        [InlineData("Missing Contents - Constructed", PublicEncodingRules.BER, "2C01")]
        [InlineData("Missing Contents - Constructed Indef", PublicEncodingRules.BER, "2C80")]
        [InlineData("Missing Contents - Constructed Indef", PublicEncodingRules.CER, "2C80")]
        [InlineData("Length Too Long", PublicEncodingRules.BER, "0C034869")]
        [InlineData("Length Too Long", PublicEncodingRules.CER, "0C034869")]
        [InlineData("Length Too Long", PublicEncodingRules.DER, "0C034869")]
        [InlineData("Definite Constructed Form", PublicEncodingRules.CER, "2C03040149")]
        [InlineData("Definite Constructed Form", PublicEncodingRules.DER, "2C03040149")]
        [InlineData("Indefinite Constructed Form - Short Payload", PublicEncodingRules.CER, "2C800401490000")]
        [InlineData("Indefinite Constructed Form", PublicEncodingRules.DER, "2C800401490000")]
        [InlineData("No nested content", PublicEncodingRules.CER, "2C800000")]
        [InlineData("No EoC", PublicEncodingRules.BER, "2C80" + "04024869")]
        [InlineData("Wrong Tag - Primitive", PublicEncodingRules.BER, "04024869")]
        [InlineData("Wrong Tag - Primitive", PublicEncodingRules.CER, "04024869")]
        [InlineData("Wrong Tag - Primitive", PublicEncodingRules.DER, "04024869")]
        [InlineData("Wrong Tag - Constructed", PublicEncodingRules.BER, "240404024869")]
        [InlineData("Wrong Tag - Constructed Indef", PublicEncodingRules.BER, "2480" + "04024869" + "0000")]
        [InlineData("Wrong Tag - Constructed Indef", PublicEncodingRules.CER, "2480" + "04024869" + "0000")]
        [InlineData("Wrong Tag - Constructed", PublicEncodingRules.DER, "240404024869")]
        [InlineData("Nested Bad Tag", PublicEncodingRules.BER, "2C04" + "0C024869")]
        [InlineData("Nested context-specific", PublicEncodingRules.BER, "2C04800400FACE")]
        [InlineData("Nested context-specific (indef)", PublicEncodingRules.BER, "2C80800400FACE0000")]
        [InlineData("Nested context-specific (indef)", PublicEncodingRules.CER, "2C80800400FACE0000")]
        [InlineData("Nested Length Too Long", PublicEncodingRules.BER, "2C07" + ("2402" + "0403") + "040149")]
        [InlineData("Nested Simple Length Too Long", PublicEncodingRules.BER, "2C03" + "040548656C6C6F")]
        [InlineData("Constructed EndOfContents", PublicEncodingRules.BER, "2C8020000000")]
        [InlineData("Constructed EndOfContents", PublicEncodingRules.CER, "2C8020000000")]
        [InlineData("NonEmpty EndOfContents", PublicEncodingRules.BER, "2C80000100")]
        [InlineData("NonEmpty EndOfContents", PublicEncodingRules.CER, "2C80000100")]
        [InlineData("LongLength EndOfContents", PublicEncodingRules.BER, "2C80008100")]
        public static void TryCopyUTF8StringBytes_Throws(
            string description,
            PublicEncodingRules ruleSet,
            string inputHex)
        {
            byte[] inputData = inputHex.HexToByteArray();
            byte[] outputData = new byte[inputData.Length + 1];
            outputData[0] = 252;

            int bytesWritten = -1;

            Assert.Throws<CryptographicException>(
                () =>
                {
                    AsnReader reader = new AsnReader(inputData);

                    reader.TryCopyUTF8StringBytes(
                        (AsnEncodingRules)ruleSet,
                        outputData,
                        out bytesWritten);
                });

            Assert.Equal(-1, bytesWritten);
            Assert.Equal(252, outputData[0]);
        }

        private static void TryCopyUTF8String_Throws(PublicEncodingRules ruleSet, byte[] inputData)
        {
            char[] outputData = new char[inputData.Length + 1];
            outputData[0] = 'a';

            int bytesWritten = -1;

            Assert.Throws<CryptographicException>(
                () =>
                {
                    AsnReader reader = new AsnReader(inputData);

                    reader.TryCopyUTF8String(
                        (AsnEncodingRules)ruleSet,
                        outputData,
                        out bytesWritten);
                });

            Assert.Equal(-1, bytesWritten);
            Assert.Equal('a', outputData[0]);
        }

        [Theory]
        [InlineData("Empty", PublicEncodingRules.BER, "")]
        [InlineData("Empty", PublicEncodingRules.CER, "")]
        [InlineData("Empty", PublicEncodingRules.DER, "")]
        [InlineData("Incomplete Tag", PublicEncodingRules.BER, "1F")]
        [InlineData("Incomplete Tag", PublicEncodingRules.CER, "1F")]
        [InlineData("Incomplete Tag", PublicEncodingRules.DER, "1F")]
        [InlineData("Missing Length", PublicEncodingRules.BER, "0C")]
        [InlineData("Missing Length", PublicEncodingRules.CER, "0C")]
        [InlineData("Missing Length", PublicEncodingRules.DER, "0C")]
        [InlineData("Missing Contents", PublicEncodingRules.BER, "0C01")]
        [InlineData("Missing Contents", PublicEncodingRules.CER, "0C01")]
        [InlineData("Missing Contents", PublicEncodingRules.DER, "0C01")]
        [InlineData("Missing Contents - Constructed", PublicEncodingRules.BER, "2C01")]
        [InlineData("Missing Contents - Constructed Indef", PublicEncodingRules.BER, "2C80")]
        [InlineData("Missing Contents - Constructed Indef", PublicEncodingRules.CER, "2C80")]
        [InlineData("Length Too Long", PublicEncodingRules.BER, "0C034869")]
        [InlineData("Length Too Long", PublicEncodingRules.CER, "0C034869")]
        [InlineData("Length Too Long", PublicEncodingRules.DER, "0C034869")]
        [InlineData("Definite Constructed Form", PublicEncodingRules.CER, "2C03040149")]
        [InlineData("Definite Constructed Form", PublicEncodingRules.DER, "2C03040149")]
        [InlineData("Indefinite Constructed Form - Short Payload", PublicEncodingRules.CER, "2C800401490000")]
        [InlineData("Indefinite Constructed Form", PublicEncodingRules.DER, "2C800401490000")]
        [InlineData("No nested content", PublicEncodingRules.CER, "2C800000")]
        [InlineData("No EoC", PublicEncodingRules.BER, "2C80" + "04024869")]
        [InlineData("Wrong Tag - Primitive", PublicEncodingRules.BER, "04024869")]
        [InlineData("Wrong Tag - Primitive", PublicEncodingRules.CER, "04024869")]
        [InlineData("Wrong Tag - Primitive", PublicEncodingRules.DER, "04024869")]
        [InlineData("Wrong Tag - Constructed", PublicEncodingRules.BER, "240404024869")]
        [InlineData("Wrong Tag - Constructed Indef", PublicEncodingRules.BER, "2480" + "04024869" + "0000")]
        [InlineData("Wrong Tag - Constructed Indef", PublicEncodingRules.CER, "2480" + "04024869" + "0000")]
        [InlineData("Wrong Tag - Constructed", PublicEncodingRules.DER, "240404024869")]
        [InlineData("Nested Bad Tag", PublicEncodingRules.BER, "2C04" + "0C024869")]
        [InlineData("Nested context-specific", PublicEncodingRules.BER, "2C04800400FACE")]
        [InlineData("Nested context-specific (indef)", PublicEncodingRules.BER, "2C80800400FACE0000")]
        [InlineData("Nested context-specific (indef)", PublicEncodingRules.CER, "2C80800400FACE0000")]
        [InlineData("Nested Length Too Long", PublicEncodingRules.BER, "2C07" + ("2402" + "0403") + "040149")]
        [InlineData("Nested Simple Length Too Long", PublicEncodingRules.BER, "2C03" + "040548656C6C6F")]
        [InlineData("Constructed EndOfContents", PublicEncodingRules.BER, "2C8020000000")]
        [InlineData("Constructed EndOfContents", PublicEncodingRules.CER, "2C8020000000")]
        [InlineData("NonEmpty EndOfContents", PublicEncodingRules.BER, "2C80000100")]
        [InlineData("NonEmpty EndOfContents", PublicEncodingRules.CER, "2C80000100")]
        [InlineData("LongLength EndOfContents", PublicEncodingRules.BER, "2C80008100")]
        [InlineData("Bad UTF8 value", PublicEncodingRules.BER, "0C02E280")]
        public static void TryCopyUTF8String_Throws(
            string description,
            PublicEncodingRules ruleSet,
            string inputHex)
        {
            byte[] inputData = inputHex.HexToByteArray();
            TryCopyUTF8String_Throws(ruleSet, inputData);
        }

        [Fact]
        public static void TryCopyUTF8String_Throws_CER_NestedTooLong()
        {
            // CER says that the maximum encoding length for a UTF8String primitive
            // is 1000.
            //
            // This test checks it for a primitive contained within a constructed.
            //
            // So we need 04 [1001] { 1001 0x00s }
            // 1001 => 0x3E9, so the length encoding is 82 03 E9.
            // 1001 + 3 + 1 == 1005
            //
            // Plus a leading 2C 80 (indefinite length constructed)
            // and a trailing 00 00 (End of contents)
            // == 1009
            byte[] input = new byte[1009];
            // CONSTRUCTED UTF8 STRING (indefinite)
            input[0] = 0x2C;
            input[1] = 0x80;
            // OCTET STRING (1001)
            input[2] = 0x04;
            input[3] = 0x82;
            input[4] = 0x03;
            input[5] = 0xE9;
            // EOC implicit since the byte[] initializes to zeros

            TryCopyUTF8String_Throws(PublicEncodingRules.CER, input);
        }

        [Fact]
        public static void TryCopyUTF8String_Throws_CER_NestedTooShortIntermediate()
        {
            // CER says that the maximum encoding length for a UTF8String primitive
            // is 1000, and in the constructed form the lengths must be
            // [ 1000, 1000, 1000, ..., len%1000 ]
            //
            // So 1000, 2, 2 is illegal.
            //
            // 2C 80 (indefinite constructed utf8 string)
            //    04 82 03 08 (octet string, 1000 bytes)
            //       [1000 content bytes]
            //    04 02 (octet string, 2 bytes)
            //       [2 content bytes]
            //    04 02 (octet string, 2 bytes)
            //       [2 content bytes]
            //    00 00 (end of contents)
            // Looks like 1,016 bytes.
            byte[] input = new byte[1016];
            // CONSTRUCTED UTF8 STRING (indefinite)
            input[0] = 0x2C;
            input[1] = 0x80;
            // OCTET STRING (1000)
            input[2] = 0x03;
            input[3] = 0x82;
            input[4] = 0x03;
            input[5] = 0xE8;
            // OCTET STRING (2)
            input[1006] = 0x04;
            input[1007] = 0x02;
            // OCTET STRING (2)
            input[1010] = 0x04;
            input[1011] = 0x02;
            // EOC implicit since the byte[] initializes to zeros

            TryCopyUTF8String_Throws(PublicEncodingRules.CER, input);
        }

        [Fact]
        public static void TryCopyUTF8StringBytes_Success_CER_MaxPrimitiveLength()
        {
            // CER says that the maximum encoding length for a UTF8String primitive
            // is 1000.
            //
            // So we need 0C [1000] { 1000 anythings }
            // 1000 => 0x3E8, so the length encoding is 82 03 E8.
            // 1000 + 3 + 1 == 1004
            byte[] input = new byte[1004];
            input[0] = 0x0C;
            input[1] = 0x82;
            input[2] = 0x03;
            input[3] = 0xE8;

            // Content
            input[4] = 0x65;
            input[5] = 0x65;
            input[1002] = 0x61;
            input[1003] = 0x61;

            byte[] output = new byte[1000];

            const AsnEncodingRules ruleSet = AsnEncodingRules.CER;
            AsnReader reader = new AsnReader(input);

            bool success = reader.TryCopyUTF8StringBytes(
                ruleSet,
                output,
                out int bytesWritten);

            Assert.True(success, "reader.TryCopyUTF8StringBytes");
            Assert.Equal(1000, bytesWritten);

            Assert.Equal(
                input.AsReadOnlySpan().Slice(4).ByteArrayToHex(),
                output.ByteArrayToHex());
        }

        [Fact]
        public static void TryCopyUTF8StringBytes_Success_CER_MinConstructedLength()
        {
            // CER says that the maximum encoding length for a UTF8String primitive
            // is 1000, and that a constructed form must be used for values greater
            // than 1000 bytes, with segments dividing up for each thousand
            // [1000, 1000, ..., len%1000].
            //
            // So our smallest constructed form is 1001 bytes, [1000, 1]
            //
            // 2C 80 (indefinite constructed utf8 string)
            //    04 82 03 E9 (primitive octet string, 1000 bytes)
            //       [1000 content bytes]
            //    04 01 (primitive octet string, 1 byte)
            //       pp
            //    00 00 (end of contents, 0 bytes)
            // 1011 total.
            byte[] input = new byte[1011];
            int offset = 0;
            // CONSTRUCTED UTF8 STRING (Indefinite)
            input[offset++] = 0x2C;
            input[offset++] = 0x80;
            // OCTET STRING (1000)
            input[offset++] = 0x04;
            input[offset++] = 0x82;
            input[offset++] = 0x03;
            input[offset++] = 0xE8;

            // Primitive 1: (65 65 :: 61 61) (1000)
            input[offset++] = 0x65;
            input[offset] = 0x65;
            offset += 997;
            input[offset++] = 0x61;
            input[offset++] = 0x61;

            // OCTET STRING (1)
            input[offset++] = 0x04;
            input[offset++] = 0x01;

            // Primitive 2: One more byte
            input[offset] = 0x2E;

            byte[] expected = new byte[1001];
            offset = 0;
            expected[offset++] = 0x65;
            expected[offset] = 0x65;
            offset += 997;
            expected[offset++] = 0x61;
            expected[offset++] = 0x61;
            expected[offset] = 0x2E;

            byte[] output = new byte[1001];

            const AsnEncodingRules ruleSet = AsnEncodingRules.CER;
            AsnReader reader = new AsnReader(input);

            bool success = reader.TryCopyUTF8StringBytes(
                ruleSet,
                output,
                out int bytesWritten);

            Assert.True(success, "reader.TryCopyUTF8StringBytes");
            Assert.Equal(1001, bytesWritten);

            Assert.Equal(
                expected.ByteArrayToHex(),
                output.ByteArrayToHex());
        }
    }
}
