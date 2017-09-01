﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography.Asn1;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Tests.Asn1
{
    public sealed class ReadObjectIdentifier : Asn1ReaderTests
    {
        [Theory]
        [InlineData("Wrong tag", PublicEncodingRules.BER, "010100")]
        [InlineData("Wrong tag", PublicEncodingRules.CER, "010100")]
        [InlineData("Wrong tag", PublicEncodingRules.DER, "010100")]
        [InlineData("Overreaching length", PublicEncodingRules.BER, "0608883703")]
        [InlineData("Overreaching length", PublicEncodingRules.CER, "0608883703")]
        [InlineData("Overreaching length", PublicEncodingRules.DER, "0608883703")]
        [InlineData("Zero length", PublicEncodingRules.BER, "0600")]
        [InlineData("Zero length", PublicEncodingRules.CER, "0600")]
        [InlineData("Zero length", PublicEncodingRules.DER, "0600")]
        [InlineData("Constructed Definite Form", PublicEncodingRules.BER, "2605" + "0603883703")]
        [InlineData("Constructed Indefinite Form", PublicEncodingRules.BER, "2680" + "0603883703" + "0000")]
        [InlineData("Constructed Indefinite Form", PublicEncodingRules.CER, "2680" + "0603883703" + "0000")]
        [InlineData("Unresolved carry-bit (first sub-identifier)", PublicEncodingRules.BER, "060188")]
        [InlineData("Unresolved carry-bit (first sub-identifier)", PublicEncodingRules.CER, "060188")]
        [InlineData("Unresolved carry-bit (first sub-identifier)", PublicEncodingRules.DER, "060188")]
        [InlineData("Unresolved carry-bit (later sub-identifier)", PublicEncodingRules.BER, "0603883781")]
        [InlineData("Unresolved carry-bit (later sub-identifier)", PublicEncodingRules.CER, "0603883781")]
        [InlineData("Unresolved carry-bit (later sub-identifier)", PublicEncodingRules.DER, "0603883781")]
        [InlineData("Sub-Identifier with leading 0x80", PublicEncodingRules.BER, "060488378001")]
        [InlineData("Sub-Identifier with leading 0x80", PublicEncodingRules.CER, "060488378001")]
        [InlineData("Sub-Identifier with leading 0x80", PublicEncodingRules.DER, "060488378001")]
        public static void ReadObjectIdentifier_Throws(
            string description,
            PublicEncodingRules ruleSet,
            string inputHex)
        {
            byte[] inputData = inputHex.HexToByteArray();

            Assert.Throws<CryptographicException>(
                () =>
                {
                    AsnReader reader = new AsnReader(inputData);
                    reader.ReadObjectIdentifier((AsnEncodingRules)ruleSet, true);
                });
        }

        [Theory]
        [InlineData(PublicEncodingRules.BER, "0603883703", "2.999.3")]
        [InlineData(PublicEncodingRules.CER, "06028837", "2.999")]
        [InlineData(PublicEncodingRules.DER, "06068837C27B0302", "2.999.8571.3.2")]
        [InlineData(PublicEncodingRules.BER, "0603550406", "2.5.4.6")]
        [InlineData(PublicEncodingRules.CER, "06092A864886F70D010105", "1.2.840.113549.1.1.5")]
        [InlineData(PublicEncodingRules.DER, "060100", "0.0")]
        [InlineData(PublicEncodingRules.BER, "06080992268993F22C63", "0.9.2342.19200300.99")]
        [InlineData(
            PublicEncodingRules.DER,
            "06156983F09DA7EBCFDEE0C7A1A7B2C0948CC8F9D77603",
            // Using the rules of ITU-T-REC-X.667-201210 for 2.25.{UUID} unregistered arcs, and
            // their sample value of f81d4fae-7dec-11d0-a765-00a0c91e6bf6
            // this is
            // { joint-iso-itu-t(2) uuid(255) thatuuid(329800735698586629295641978511506172918) three(3) }
            "2.25.329800735698586629295641978511506172918.3")]
        public static void ReadObjectIdentifierAsString_Success(
            PublicEncodingRules ruleSet,
            string inputHex,
            string expectedValue)
        {
            byte[] inputData = inputHex.HexToByteArray();
            AsnReader reader = new AsnReader(inputData);

            string oidValue = reader.ReadObjectIdentifierAsString((AsnEncodingRules)ruleSet);
            Assert.Equal(expectedValue, oidValue);
        }

        [Theory]
        [InlineData(PublicEncodingRules.BER, "06082A864886F70D0307", false, "3des")]
        [InlineData(PublicEncodingRules.CER, "06082A864886F70D0307", true, "1.2.840.113549.3.7")]
        [InlineData(PublicEncodingRules.DER, "0609608648016503040201", true, "2.16.840.1.101.3.4.2.1")]
        [InlineData(PublicEncodingRules.BER, "0609608648016503040201", false, "sha256")]
        public static void ReadObjectIdentifier_SkipFriendlyName(
            PublicEncodingRules ruleSet,
            string inputHex,
            bool skipFriendlyName,
            string expectedFriendlyName)
        {
            byte[] inputData = inputHex.HexToByteArray();
            AsnReader reader = new AsnReader(inputData);

            Oid oid = reader.ReadObjectIdentifier((AsnEncodingRules)ruleSet, skipFriendlyName);
            Assert.Equal(expectedFriendlyName, oid.FriendlyName);
        }
    }
}
