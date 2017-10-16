﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Security.Cryptography.Asn1;
using Xunit;

namespace System.Security.Cryptography.Tests.Asn1
{
    public class WriteUtcTime : Asn1WriterTests
    {
        public static IEnumerable<object[]> TestCases { get; } = new object[][]
        {
            new object[]
            {
                new DateTimeOffset(2017, 10, 16, 8, 24, 3, TimeSpan.FromHours(-7)),
                "0D3137313031363135323430335A",
            },
            new object[]
            {
                new DateTimeOffset(1817, 10, 16, 21, 24, 3, TimeSpan.FromHours(6)),
                "0D3137313031363135323430335A",
            },
            new object[]
            {
                new DateTimeOffset(3000, 1, 1, 0, 0, 0, TimeSpan.Zero),
                "0D3030303130313030303030305A",
            }, 
        };

        [Theory]
        [MemberData(nameof(TestCases))]
        public void VerifyWriteUtcTime_BER(DateTimeOffset input, string expectedHexPayload)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.BER);
            writer.WriteUtcTime(input);

            Verify(writer, "17" + expectedHexPayload);
        }

        [Theory]
        [MemberData(nameof(TestCases))]
        public void VerifyWriteUtcTime_BER_CustomTag(DateTimeOffset input, string expectedHexPayload)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.BER);
            Asn1Tag tag = new Asn1Tag(TagClass.Application, 11);
            writer.WriteUtcTime(tag, input);

            Verify(writer, Stringify(tag) + expectedHexPayload);
        }

        [Theory]
        [MemberData(nameof(TestCases))]
        public void VerifyWriteUtcTime_CER(DateTimeOffset input, string expectedHexPayload)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.CER);
            writer.WriteUtcTime(input);

            Verify(writer, "17" + expectedHexPayload);
        }

        [Theory]
        [MemberData(nameof(TestCases))]
        public void VerifyWriteUtcTime_CER_CustomTag(DateTimeOffset input, string expectedHexPayload)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.CER);
            Asn1Tag tag = new Asn1Tag(TagClass.Private, 95);
            writer.WriteUtcTime(tag, input);

            Verify(writer, Stringify(tag) + expectedHexPayload);
        }

        [Theory]
        [MemberData(nameof(TestCases))]
        public void VerifyWriteUtcTime_DER(DateTimeOffset input, string expectedHexPayload)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            writer.WriteUtcTime(input);

            Verify(writer, "17" + expectedHexPayload);
        }

        [Theory]
        [MemberData(nameof(TestCases))]
        public void VerifyWriteUtcTime_DER_CustomTag(DateTimeOffset input, string expectedHexPayload)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            Asn1Tag tag = new Asn1Tag(TagClass.ContextSpecific, 3);
            writer.WriteUtcTime(tag, input);

            Verify(writer, Stringify(tag) + expectedHexPayload);
        }

        [Theory]
        [InlineData(PublicEncodingRules.BER)]
        [InlineData(PublicEncodingRules.CER)]
        [InlineData(PublicEncodingRules.DER)]
        public void VerifyWriteUtcTime_EndOfContents(PublicEncodingRules ruleSet)
        {
            AsnWriter writer = new AsnWriter((AsnEncodingRules)ruleSet);

            AssertExtensions.Throws<ArgumentException>(
                "tag",
                () => writer.WriteUtcTime(Asn1Tag.EndOfContents, DateTimeOffset.Now));
        }
    }
}
