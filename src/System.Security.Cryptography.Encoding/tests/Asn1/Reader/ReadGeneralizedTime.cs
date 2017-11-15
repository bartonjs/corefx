﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography.Asn1;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Tests.Asn1
{
    public sealed class ReadGeneralizedTime : Asn1ReaderTests
    {
        [Theory]
        // yyyyMMddHH (2017090821)
        [InlineData(PublicEncodingRules.BER, "180A32303137303930383231", 2017, 9, 8, 21, 0, 0, 0, null, 0)]
        // yyyyMMddHHZ (2017090821Z)
        [InlineData(PublicEncodingRules.BER, "180B323031373039303832315A", 2017, 9, 8, 21, 0, 0, 0, 0, 0)]
        // yyyyMMddHH-HH (2017090821-01)
        [InlineData(PublicEncodingRules.BER, "180D323031373039303832312D3031", 2017, 9, 8, 21, 0, 0, 0, -1, 0)]
        // yyyyMMddHH+HHmm (2017090821+0118)
        [InlineData(PublicEncodingRules.BER, "180F323031373039303832312B30313138", 2017, 9, 8, 21, 0, 0, 0, 1, 18)]
        // yyyyMMddHH-HH:mm (2017090821-01:18)
        [InlineData(PublicEncodingRules.BER, "1810323031373039303832312D30313A3138", 2017, 9, 8, 21, 0, 0, 0, -1, -18)]
        // yyyyMMddHH,hourFrac (2017090821.1)
        [InlineData(PublicEncodingRules.BER, "180C323031373039303832312C31", 2017, 9, 8, 21, 6, 0, 0, null, 0)]
        // yyyyMMddHH.hourFracZ (2017090821.2010Z)
        [InlineData(PublicEncodingRules.BER, "1810323031373039303832312E323031305A", 2017, 9, 8, 21, 12, 3, 600, 0, 0)]
        // yyyyMMddHH,hourFrac-HH (2017090821,3099-01)
        [InlineData(PublicEncodingRules.BER, "1812323031373039303832312C333039392D3031", 2017, 9, 8, 21, 18, 35, 640, -1, 0)]
        // yyyyMMddHH.hourFrac+HHmm (2017090821.201+0118)
        [InlineData(PublicEncodingRules.BER, "1813323031373039303832312E3230312B30313138", 2017, 9, 8, 21, 12, 3, 600, 1, 18)]
        // yyyyMMddHH.hourFrac-HH:mm (2017090821.1-01:18)
        [InlineData(PublicEncodingRules.BER, "1812323031373039303832312E312D30313A3138", 2017, 9, 8, 21, 6, 0, 0, -1, -18)]
        // yyyyMMddHHmm (201709082358)
        [InlineData(PublicEncodingRules.BER, "180C323031373039303832333538", 2017, 9, 8, 23, 58, 0, 0, null, 0)]
        // yyyyMMddHHmmZ (201709082358Z)
        [InlineData(PublicEncodingRules.BER, "180D3230313730393038323335385A", 2017, 9, 8, 23, 58, 0, 0, 0, 0)]
        // yyyyMMddHHmm-HH (201709082358-01)
        [InlineData(PublicEncodingRules.BER, "180F3230313730393038323335382D3031", 2017, 9, 8, 23, 58, 0, 0, -1, 0)]
        // yyyyMMddHHmm+HHmm (201709082358+0118)
        [InlineData(PublicEncodingRules.BER, "18113230313730393038323335382B30313138", 2017, 9, 8, 23, 58, 0, 0, 1, 18)]
        // yyyyMMddHHmm-HH:mm (201709082358-01:18)
        [InlineData(PublicEncodingRules.BER, "18123230313730393038323335382D30313A3138", 2017, 9, 8, 23, 58, 0, 0, -1, -18)]
        // yyyyMMddHHmm.minuteFrac (201709082358.01)
        [InlineData(PublicEncodingRules.BER, "180F3230313730393038323335382E3031", 2017, 9, 8, 23, 58, 0, 600, null, 0)]
        // yyyyMMddHHmm,minuteFracZ (201709082358,11Z)
        [InlineData(PublicEncodingRules.BER, "18103230313730393038323335382C31315A", 2017, 9, 8, 23, 58, 6, 600, 0, 0)]
        // yyyyMMddHHmm.minuteFrac-HH (201709082358.05-01)
        [InlineData(PublicEncodingRules.BER, "18123230313730393038323335382E30352D3031", 2017, 9, 8, 23, 58, 3, 0, -1, 0)]
        // yyyyMMddHHmm,minuteFrac+HHmm (201709082358,007+0118)
        [InlineData(PublicEncodingRules.BER, "18153230313730393038323335382C3030372B30313138", 2017, 9, 8, 23, 58, 0, 420, 1, 18)]
        // yyyyMMddHHmm.minuteFrac-HH:mm (201709082358.00005-01:18)
        [InlineData(PublicEncodingRules.BER, "18183230313730393038323335382E30303030352D30313A3138", 2017, 9, 8, 23, 58, 0, 3, -1, -18)]
        // yyyyMMddHHmmss (20161106012345) - Ambiguous time due to DST "fall back" in US & Canada
        [InlineData(PublicEncodingRules.BER, "180E3230313631313036303132333435", 2016, 11, 6, 1, 23, 45, 0, null, 0)]
        // yyyyMMddHHmmssZ (20161106012345Z)
        [InlineData(PublicEncodingRules.BER, "180F32303136313130363031323334355A", 2016, 11, 6, 1, 23, 45, 0, 0, 0)]
        // yyyyMMddHHmmss-HH (20161106012345-01)
        [InlineData(PublicEncodingRules.BER, "181132303136313130363031323334352D3031", 2016, 11, 6, 1, 23, 45, 0, -1, 0)]
        // yyyyMMddHHmmss+HHmm (20161106012345+0118)
        [InlineData(PublicEncodingRules.BER, "181332303136313130363031323334352B30313138", 2016, 11, 6, 1, 23, 45, 0, 1, 18)]
        // yyyyMMddHHmmss-HH:mm (20161106012345-01:18)
        [InlineData(PublicEncodingRules.BER, "181432303136313130363031323334352D30313A3138", 2016, 11, 6, 1, 23, 45, 0, -1, -18)]
        // yyyyMMddHHmmss.secondFrac (20161106012345.6789) - Ambiguous time due to DST "fall back" in US & Canada
        [InlineData(PublicEncodingRules.BER, "181332303136313130363031323334352E36373839", 2016, 11, 6, 1, 23, 45, 679, null, 0)]
        // yyyyMMddHHmmss,secondFracZ (20161106012345,7654Z)
        [InlineData(PublicEncodingRules.BER, "181432303136313130363031323334352C373635345A", 2016, 11, 6, 1, 23, 45, 765, 0, 0)]
        // yyyyMMddHHmmss.secondFrac-HH (20161106012345.001-01)
        [InlineData(PublicEncodingRules.BER, "181532303136313130363031323334352E3030312D3031", 2016, 11, 6, 1, 23, 45, 1, -1, 0)]
        // yyyyMMddHHmmss,secondFrac+HHmm (20161106012345,0009+0118)
        [InlineData(PublicEncodingRules.BER, "181832303136313130363031323334352C303030392B30313138", 2016, 11, 6, 1, 23, 45, 1, 1, 18)]
        // yyyyMMddHHmmss.secondFrac-HH:mm (20161106012345.9999-01:18)
        [InlineData(PublicEncodingRules.BER, "181932303136313130363031323334352E393939392D30313A3138", 2016, 11, 6, 1, 23, 46, 0, -1, -18)]

        // yyyyMMddHHmmssZ (20161106012345Z)
        [InlineData(PublicEncodingRules.CER, "180F32303136313130363031323334355A", 2016, 11, 6, 1, 23, 45, 0, 0, 0)]
        [InlineData(PublicEncodingRules.DER, "180F32303136313130363031323334355A", 2016, 11, 6, 1, 23, 45, 0, 0, 0)]

        // yyyyMMddHHmmss.secondFracZ (20161106012345,7654Z)
        [InlineData(PublicEncodingRules.CER, "181432303136313130363031323334352E373635345A", 2016, 11, 6, 1, 23, 45, 765, 0, 0)]
        [InlineData(PublicEncodingRules.DER, "181432303136313130363031323334352E373635345A", 2016, 11, 6, 1, 23, 45, 765, 0, 0)]
        public static void ParseTime_Valid(
            PublicEncodingRules ruleSet,
            string inputHex,
            int year,
            int month,
            int day,
            int hour,
            int minute,
            int second,
            int millisecond,
            int? offsetHour,
            int offsetMinute)
        {
            byte[] inputData = inputHex.HexToByteArray();

            AsnReader reader = new AsnReader(inputData, (AsnEncodingRules)ruleSet);
            DateTimeOffset value = reader.GetGeneralizedTime();
            Assert.False(reader.HasData, "reader.HasData");

            Assert.Equal(year, value.Year);
            Assert.Equal(month, value.Month);
            Assert.Equal(day, value.Day);
            Assert.Equal(hour, value.Hour);
            Assert.Equal(minute, value.Minute);
            Assert.Equal(second, value.Second);
            Assert.Equal(millisecond, value.Millisecond);

            TimeSpan timeOffset;

            if (offsetHour == null)
            {
                // Ask the system what offset it thinks was relevant for that time.
                // Includes DST ambiguity.
                timeOffset = new DateTimeOffset(value.LocalDateTime).Offset;
            }
            else
            {
                timeOffset = new TimeSpan(offsetHour.Value, offsetMinute, 0);
            }

            Assert.Equal(timeOffset, value.Offset);
        }

        [Theory]
        // yyyyMMddHH (2017090821)
        [InlineData("180A32303137303930383231")]
        // yyyyMMddHHZ (2017090821Z)
        [InlineData("180B323031373039303832315A")]
        // yyyyMMddHH-HH (2017090821-01)
        [InlineData("180D323031373039303832312D3031")]
        // yyyyMMddHH+HHmm (2017090821+0118)
        [InlineData("180F323031373039303832312B30313138")]
        // yyyyMMddHH-HH:mm (2017090821-01:18)
        [InlineData("1810323031373039303832312D30313A3138")]
        // yyyyMMddHH,hourFrac (2017090821,1)
        [InlineData("180C323031373039303832312C31")]
        // yyyyMMddHH.hourFrac (2017090821.1)
        [InlineData("180C323031373039303832312E31")]
        // yyyyMMddHH,hourFracZ (2017090821,2010Z)
        [InlineData("1810323031373039303832312C323031305A")]
        // yyyyMMddHH.hourFracZ (2017090821.2010Z)
        [InlineData("1810323031373039303832312E323031305A")]
        // yyyyMMddHH,hourFrac-HH (2017090821,3099-01)
        [InlineData("1812323031373039303832312C333039392D3031")]
        // yyyyMMddHH.hourFrac-HH (2017090821.3099-01)
        [InlineData("1812323031373039303832312E333039392D3031")]
        // yyyyMMddHH,hourFrac+HHmm (2017090821,201+0118)
        [InlineData("1813323031373039303832312C3230312B30313138")]
        // yyyyMMddHH.hourFrac+HHmm (2017090821.201+0118)
        [InlineData("1813323031373039303832312E3230312B30313138")]
        // yyyyMMddHH,hourFrac-HH:mm (2017090821,1-01:18)
        [InlineData("1812323031373039303832312C312D30313A3138")]
        // yyyyMMddHH.hourFrac-HH:mm (2017090821.1-01:18)
        [InlineData("1812323031373039303832312E312D30313A3138")]
        // yyyyMMddHHmm (201709082358)
        [InlineData("180C323031373039303832333538")]
        // yyyyMMddHHmmZ (201709082358Z)
        [InlineData("180D3230313730393038323335385A")]
        // yyyyMMddHHmm-HH (201709082358-01)
        [InlineData("180F3230313730393038323335382D3031")]
        // yyyyMMddHHmm+HHmm (201709082358+0118)
        [InlineData("18113230313730393038323335382B30313138")]
        // yyyyMMddHHmm-HH:mm (201709082358-01:18)
        [InlineData("18123230313730393038323335382D30313A3138")]
        // yyyyMMddHHmm,minuteFrac (201709082358,01)
        [InlineData("180F3230313730393038323335382C3031")]
        // yyyyMMddHHmm.minuteFrac (201709082358.01)
        [InlineData("180F3230313730393038323335382E3031")]
        // yyyyMMddHHmm,minuteFracZ (201709082358,11Z)
        [InlineData("18103230313730393038323335382C31315A")]
        // yyyyMMddHHmm.minuteFracZ (201709082358.11Z)
        [InlineData("18103230313730393038323335382E31315A")]
        // yyyyMMddHHmm,minuteFrac-HH (201709082358m05-01)
        [InlineData("18123230313730393038323335382C30352D3031")]
        // yyyyMMddHHmm.minuteFrac-HH (201709082358.05-01)
        [InlineData("18123230313730393038323335382E30352D3031")]
        // yyyyMMddHHmm,minuteFrac+HHmm (201709082358,007+0118)
        [InlineData("18153230313730393038323335382C3030372B30313138")]
        // yyyyMMddHHmm.minuteFrac+HHmm (201709082358.007+0118)
        [InlineData("18153230313730393038323335382E3030372B30313138")]
        // yyyyMMddHHmm,minuteFrac-HH:mm (201709082358,00005-01:18)
        [InlineData("18183230313730393038323335382C30303030352D30313A3138")]
        // yyyyMMddHHmm.minuteFrac-HH:mm (201709082358.00005-01:18)
        [InlineData("18183230313730393038323335382E30303030352D30313A3138")]
        // yyyyMMddHHmmss (20161106012345)
        [InlineData("180E3230313631313036303132333435")]
        // yyyyMMddHHmmss-HH (20161106012345-01)
        [InlineData("181132303136313130363031323334352D3031")]
        // yyyyMMddHHmmss+HHmm (20161106012345+0118)
        [InlineData("181332303136313130363031323334352B30313138")]
        // yyyyMMddHHmmss-HH:mm (20161106012345-01:18)
        [InlineData("181432303136313130363031323334352D30313A3138")]
        // yyyyMMddHHmmss,secondFrac (20161106012345,6789)
        [InlineData("181332303136313130363031323334352C36373839")]
        // yyyyMMddHHmmss.secondFrac (20161106012345.6789)
        [InlineData("181332303136313130363031323334352E36373839")]
        // yyyyMMddHHmmss,secondFracZ (20161106012345,7654Z)
        [InlineData("181432303136313130363031323334352C373635345A")]
        // yyyyMMddHHmmss,secondFrac-HH (20161106012345,001-01)
        [InlineData("181532303136313130363031323334352C3030312D3031")]
        // yyyyMMddHHmmss.secondFrac-HH (20161106012345.001-01)
        [InlineData("181532303136313130363031323334352E3030312D3031")]
        // yyyyMMddHHmmss,secondFrac+HHmm (20161106012345,0009+0118)
        [InlineData("181832303136313130363031323334352C303030392B30313138")]
        // yyyyMMddHHmmss.secondFrac+HHmm (20161106012345.0009+0118)
        [InlineData("181832303136313130363031323334352E303030392B30313138")]
        // yyyyMMddHHmmss,secondFrac-HH:mm (20161106012345,9999-01:18)
        [InlineData("181932303136313130363031323334352C393939392D30313A3138")]
        // yyyyMMddHHmmss.secondFrac-HH:mm (20161106012345.9999-01:18)
        [InlineData("181932303136313130363031323334352E393939392D30313A3138")]
        // yyyyMMddHHmmss.secondFrac0Z (20161106012345.76540Z)
        [InlineData("181532303136313130363031323334352E37363534305A")]
        // Constructed encoding of yyyyMMddHHmmssZ
        [InlineData(
            "3880" +
              "040432303136" +
              "04023131" +
              "0403303630" +
              "040131" +
              "0405323334355A" +
              "0000")]
        public static void ParseTime_BerOnly(string inputHex)
        {
            byte[] inputData = inputHex.HexToByteArray();
            AsnReader cerReader = new AsnReader(inputData, AsnEncodingRules.CER);
            AsnReader derReader = new AsnReader(inputData, AsnEncodingRules.DER);

            Assert.Throws<CryptographicException>(() => cerReader.GetGeneralizedTime());
            Assert.Throws<CryptographicException>(() => derReader.GetGeneralizedTime());

            // Prove it was not just corrupt input
            AsnReader berReader = new AsnReader(inputData, AsnEncodingRules.BER);
            berReader.GetGeneralizedTime();
            Assert.False(berReader.HasData, "berReader.HasData");
            Assert.True(cerReader.HasData, "cerReader.HasData");
            Assert.True(derReader.HasData, "derReader.HasData");
        }

        [Fact]
        public static void ExcessivelyPreciseFraction()
        {
            byte[] inputData = Text.Encoding.ASCII.GetBytes("\u0018\u002A2017092118.012345678901234567890123456789Z");

            AsnReader berReader = new AsnReader(inputData, AsnEncodingRules.BER);
            DateTimeOffset value = berReader.GetGeneralizedTime();
            Assert.False(berReader.HasData, "berReader.HasData");

            DateTimeOffset expected = new DateTimeOffset(2017, 9, 21, 18, 0, 44, 444, TimeSpan.Zero);

            Assert.Equal(expected, value);
        }

        [Fact]
        public static void ExcessivelyPreciseNonFraction()
        {
            byte[] inputData = Text.Encoding.ASCII.GetBytes("\u0018\u002A2017092118.012345678901234567890123Q56789Z");
            AsnReader berReader = new AsnReader(inputData, AsnEncodingRules.BER);

            Assert.Throws<CryptographicException>(() => berReader.GetGeneralizedTime());
        }

        [Theory]
        // yyyyMMddHH,hourFrac (2017090821,1)
        [InlineData("180C323031373039303832312C31")]
        // yyyyMMddHH.hourFrac (2017090821.1)
        [InlineData("180C323031373039303832312E31")]
        // yyyyMMddHH,hourFracZ (2017090821,2010Z)
        [InlineData("1810323031373039303832312C323031305A")]
        // yyyyMMddHH.hourFracZ (2017090821.2010Z)
        [InlineData("1810323031373039303832312E323031305A")]
        // yyyyMMddHH,hourFrac-HH (2017090821,3099-01)
        [InlineData("1812323031373039303832312C333039392D3031")]
        // yyyyMMddHH.hourFrac-HH (2017090821.3099-01)
        [InlineData("1812323031373039303832312E333039392D3031")]
        // yyyyMMddHH,hourFrac+HHmm (2017090821,201+0118)
        [InlineData("1813323031373039303832312C3230312B30313138")]
        // yyyyMMddHH.hourFrac+HHmm (2017090821.201+0118)
        [InlineData("1813323031373039303832312E3230312B30313138")]
        // yyyyMMddHH,hourFrac-HH:mm (2017090821,1-01:18)
        [InlineData("1812323031373039303832312C312D30313A3138")]
        // yyyyMMddHH.hourFrac-HH:mm (2017090821.1-01:18)
        [InlineData("1812323031373039303832312E312D30313A3138")]
        // yyyyMMddHHmm,minuteFrac (201709082358,01)
        [InlineData("180F3230313730393038323335382C3031")]
        // yyyyMMddHHmm.minuteFrac (201709082358.01)
        [InlineData("180F3230313730393038323335382E3031")]
        // yyyyMMddHHmm,minuteFracZ (201709082358,11Z)
        [InlineData("18103230313730393038323335382C31315A")]
        // yyyyMMddHHmm.minuteFracZ (201709082358.11Z)
        [InlineData("18103230313730393038323335382E31315A")]
        // yyyyMMddHHmm,minuteFrac-HH (201709082358m05-01)
        [InlineData("18123230313730393038323335382C30352D3031")]
        // yyyyMMddHHmm.minuteFrac-HH (201709082358.05-01)
        [InlineData("18123230313730393038323335382E30352D3031")]
        // yyyyMMddHHmm,minuteFrac+HHmm (201709082358,007+0118)
        [InlineData("18153230313730393038323335382C3030372B30313138")]
        // yyyyMMddHHmm.minuteFrac+HHmm (201709082358.007+0118)
        [InlineData("18153230313730393038323335382E3030372B30313138")]
        // yyyyMMddHHmm,minuteFrac-HH:mm (201709082358,00005-01:18)
        [InlineData("18183230313730393038323335382C30303030352D30313A3138")]
        // yyyyMMddHHmm.minuteFrac-HH:mm (201709082358.00005-01:18)
        [InlineData("18183230313730393038323335382E30303030352D30313A3138")]
        // yyyyMMddHHmmss,secondFrac (20161106012345,6789)
        [InlineData("181332303136313130363031323334352C36373839")]
        // yyyyMMddHHmmss.secondFrac (20161106012345.6789)
        [InlineData("181332303136313130363031323334352E36373839")]
        // yyyyMMddHHmmss,secondFracZ (20161106012345,7654Z)
        [InlineData("181432303136313130363031323334352C373635345A")]
        // yyyyMMddHHmmss,secondFrac-HH (20161106012345,001-01)
        [InlineData("181532303136313130363031323334352C3030312D3031")]
        // yyyyMMddHHmmss.secondFrac-HH (20161106012345.001-01)
        [InlineData("181532303136313130363031323334352E3030312D3031")]
        // yyyyMMddHHmmss,secondFrac+HHmm (20161106012345,0009+0118)
        [InlineData("181832303136313130363031323334352C303030392B30313138")]
        // yyyyMMddHHmmss.secondFrac+HHmm (20161106012345.0009+0118)
        [InlineData("181832303136313130363031323334352E303030392B30313138")]
        // yyyyMMddHHmmss,secondFrac-HH:mm (20161106012345,9999-01:18)
        [InlineData("181932303136313130363031323334352C393939392D30313A3138")]
        // yyyyMMddHHmmss.secondFrac-HH:mm (20161106012345.9999-01:18)
        [InlineData("181932303136313130363031323334352E393939392D30313A3138")]
        // yyyyMMddHHmmss.secondFrac0Z (20161106012345.76540Z)
        [InlineData("181532303136313130363031323334352E37363534305A")]
        public static void VerifyDisallowFraction_BER(string inputHex)
        {
            byte[] inputData = inputHex.HexToByteArray();

            AsnReader berReader = new AsnReader(inputData, AsnEncodingRules.BER);

            Assert.Throws<CryptographicException>(() => berReader.GetGeneralizedTime(disallowFractions: true));
            
            // Legit if the fraction is allowed
            berReader.GetGeneralizedTime();
            Assert.False(berReader.HasData, "berReader.HasData");
        }

        [Theory]
        [InlineData("Wrong Tag", "170F32303136313130363031323334355A")]
        [InlineData("Incomplete Tag", "1F")]
        [InlineData("No Length", "18")]
        [InlineData("No payload", "180F")]
        [InlineData("Length exceeds content", "181032303136313130363031323334355A")]
        [InlineData("yyyyMMdd", "18083230313631313036")]
        [InlineData("yyyyMMddZ", "180932303136313130365A")]
        [InlineData("yyyyMMdd+HH", "180B32303136313130362D3030")]
        [InlineData("yyyyMMdd-HHmm", "180D32303136313130362B30303030")]
        [InlineData("yyyyMMddH", "1809323031363131303630")]
        [InlineData("yyyyMMddHZ", "180A3230313631313036305A")]
        [InlineData("yQyyMMddHH", "180A32513136313130363031")]
        [InlineData("yyyyMQddHH", "180A32303136315130363031")]
        [InlineData("yyyyMMQdHH", "180A32303136313151363031")]
        [InlineData("yyyyMMddHQ", "180A32303136313130363051")]
        [InlineData("yyyyMMddHH,", "180B323031363131303630312C")]
        [InlineData("yyyyMMddHH.", "180B323031363131303630312E")]
        [InlineData("yyyyMMddHHQ", "180B3230313631313036303151")]
        [InlineData("yyyyMMddHH,Q", "180C323031363131303630312C51")]
        [InlineData("yyyyMMddHH.Q", "180C323031363131303630312E51")]
        [InlineData("yyyyMMddHH..", "180C323031363131303630312E2E")]
        [InlineData("yyyyMMddHH-", "180B323031363131303630312B")]
        [InlineData("yyyyMMddHH+", "180B323031363131303630312D")]
        [InlineData("yyyyMMddHHmQ", "180C323031363131303630313251")]
        [InlineData("yyyyMMddHHm+", "180C32303136313130363031322D")]
        [InlineData("yyyyMMddHHmmQ", "180D32303136313130363031323351")]
        [InlineData("yyyyMMddHHmm-", "180D3230313631313036303132332B")]
        [InlineData("yyyyMMddHHmm,", "180D3230313631313036303132332C")]
        [InlineData("yyyyMMddHHmm+", "180D3230313631313036303132332D")]
        [InlineData("yyyyMMddHHmm.", "180D3230313631313036303132332E")]
        [InlineData("yyyyMMddHHmm+Q", "180E3230313631313036303132332D51")]
        [InlineData("yyyyMMddHHmm.Q", "180E3230313631313036303132332E51")]
        [InlineData("yyyyMMddHHmm..", "180E3230313631313036303132332E2E")]
        [InlineData("yyyyMMddHHmms", "180D32303136313130363031323334")]
        [InlineData("yyyyMMddHHmmsQ", "180E3230313631313036303132333451")]
        [InlineData("yyyyMMddHHmmss-", "180F32303136313130363031323334352B")]
        [InlineData("yyyyMMddHHmmss,", "180F32303136313130363031323334352C")]
        [InlineData("yyyyMMddHHmmss+", "180F32303136313130363031323334352D")]
        [InlineData("yyyyMMddHHmmss.", "180F32303136313130363031323334352E")]
        [InlineData("yyyyMMddHHmmssQ", "180F323031363131303630313233343551")]
        [InlineData("yyyyMMddHHmmss.Q", "181032303136313130363031323334352E51")]
        [InlineData("yyyyMMddHHmmss.Q", "181032303136313130363031323334352E2E")]
        [InlineData("yyyyMMddHHZmm", "180D323031363131303630315A3233")]
        [InlineData("yyyyMMddHHmmZss", "180F3230313631313036303132335A3435")]
        [InlineData("yyyyMMddHHmmssZ.s", "181232303136313130363031323334355A2E36")]
        [InlineData("yyyyMMddHH+H", "180C323031363131303630312D30")]
        [InlineData("yyyyMMddHH+HQ", "180D323031363131303630312D3051")]
        [InlineData("yyyyMMddHH+HHQ", "180E323031363131303630312D303051")]
        [InlineData("yyyyMMddHH+HHmQ", "180F323031363131303630312D30303051")]
        [InlineData("yyyyMMddHH+HHmmQ", "1810323031363131303630312D3030303151")]
        [InlineData("yyyyMMddHH+HH:mQ", "1810323031363131303630312D30303A3051")]
        [InlineData("yyyyMMddHH+HH:mmQ", "1811323031363131303630312D30303A303051")]
        public static void GetGeneralizedTime_Throws(string description, string inputHex)
        {
            byte[] inputData = inputHex.HexToByteArray();
            AsnReader reader = new AsnReader(inputData, AsnEncodingRules.BER);

            Assert.Throws<CryptographicException>(() => reader.GetGeneralizedTime());
        }
    }
}
