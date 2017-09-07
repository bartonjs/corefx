﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;
using Test.Cryptography;
using Xunit;

using PublicEncodingRules=System.Security.Cryptography.Tests.Asn1.Asn1ReaderTests.PublicEncodingRules;

namespace System.Security.Cryptography.Tests.Asn1
{
    public class SimpleDeserialize
    {
        [Theory]
        [InlineData(
            PublicEncodingRules.BER,
            "3080" + "06072A8648CE3D0201" + "06082A8648CE3D030107" + "0000",
            "1.2.840.10045.3.1.7")]
        // More!
        public static void AlgorithmIdentifier_ECC_WithCurves(
            PublicEncodingRules ruleSet,
            string inputHex,
            string curveOid)
        {
            byte[] inputData = inputHex.HexToByteArray();

            var algorithmIdentifier = AsnSerializer.Deserialize<AlgorithmIdentifier>(
                inputData,
                (AsnEncodingRules)ruleSet,
                out int bytesRead);

            Assert.Equal("1.2.840.10045.2.1", algorithmIdentifier.Algorithm.Value);
            
            var reader = new AsnReader(algorithmIdentifier.Parameters, (AsnEncodingRules)ruleSet);
            Oid curveId = reader.ReadObjectIdentifier(skipFriendlyName: true);
            Assert.Equal(curveOid, curveId.Value);
        }

        [Fact]
        public static void AllTheSimpleThings()
        {
            const string InputHex =
                "3080" +
                  "0101FF" +
                  "0201FE" +
                  "020101" +
                  "0202FEFF" +
                  "02020101" +
                  "0204FEFFFFFF" +
                  "020401000001" +
                  "0208FEFFFFFFFFFFFFFF" +
                  "02080100000000000001" +
                  "0209010000000000000001" +
                  "0303000102" +
                  "0404FF0055AA" +
                  "0500" +
                  "06082A8648CE3D030107" +
                  "06072A8648CE3D0201" +
                  "06092A864886F70D010101" +
                  "0A011E" +
                  "0C2544722E2026204D72732E20536D697468E280904A6F6E657320EFB9A0206368696C6472656E" +
                  "162144722E2026204D72732E20536D6974682D4A6F6E65732026206368696C6472656E" +
                  "1E42" +
                    "00440072002E002000260020004D00720073002E00200053006D006900740068" +
                    "2010004A006F006E006500730020FE600020006300680069006C006400720065" +
                    "006E" +
                  "3080" +
                    "010100" +
                    "010100" +
                    "0101FF" +
                    "0101FF" +
                    "010100" +
                    "0000" +
                  "3180" +
                    "020100" +
                    "020101" +
                    "0201FE" +
                    "0201FF" +
                    "02020100" +
                    "0000" +
                  "0000";

            byte[] inputData = InputHex.HexToByteArray();

            var atst = AsnSerializer.Deserialize<AllTheSimpleThings>(
                inputData,
                AsnEncodingRules.BER,
                out _);

            const string UnicodeVerifier = "Dr. & Mrs. Smith\u2010Jones \uFE60 children";
            const string AsciiVerifier = "Dr. & Mrs. Smith-Jones & children";

            Assert.False(atst.NotBool, "atst.NotBool");
            Assert.Equal(-2, atst.SByte);
            Assert.Equal(1, atst.Byte);
            Assert.Equal(unchecked((short)0xFEFF), atst.Short);
            Assert.Equal(0x0101, atst.UShort);
            Assert.Equal(unchecked((int)0xFEFFFFFF), atst.Int);
            Assert.Equal((uint)0x01000001, atst.UInt);
            Assert.Equal(unchecked((long)0xFEFFFFFFFFFFFFFF), atst.Long);
            Assert.Equal(0x0100000000000001UL, atst.ULong);
            Assert.Equal("010000000000000001", atst.BigIntBytes.ByteArrayToHex());
            Assert.Equal("0102", atst.BitStringBytes.ByteArrayToHex());
            Assert.Equal("FF0055AA", atst.OctetStringBytes.ByteArrayToHex());
            Assert.Equal("0500", atst.Null.ByteArrayToHex());
            Assert.Equal("1.2.840.10045.3.1.7", atst.UnattrOid.Value);
            Assert.Equal("1.2.840.10045.3.1.7", atst.UnattrOid.FriendlyName);
            Assert.Equal("1.2.840.10045.2.1", atst.WithName.Value);
            Assert.Equal("ECC", atst.WithName.FriendlyName);
            Assert.Equal("1.2.840.113549.1.1.1", atst.OidString);
            Assert.Equal(UniversalTagNumber.BMPString, atst.LinearEnum);
            Assert.Equal(UnicodeVerifier, atst.Utf8Encoded);
            Assert.Equal(AsciiVerifier, atst.Ia5Encoded);
            Assert.Equal(UnicodeVerifier, atst.BmpEncoded);
            Assert.Equal(new[] { false, false, true, true, false }, atst.Bools);
            Assert.Equal(new[] { 0, 1, -2, -1, 256 }, atst.Ints);
        }

        [Fact]
        public static void ReadEcPublicKey()
        {
            const string PublicKeyValue =
                "04" +
                "2363DD131DA65E899A2E63E9E05E50C830D4994662FFE883DB2B9A767DCCABA2" +
                "F07081B5711BE1DEE90DFC8DE17970C2D937A16CD34581F52B8D59C9E9532D13";

            const string InputHex =
                "3059" +
                  "3013" +
                    "06072A8648CE3D0201" +
                    "06082A8648CE3D030107" +
                  "0342" +
                    "00" +
                    PublicKeyValue;

            byte[] inputData = InputHex.HexToByteArray();

            var spki = AsnSerializer.Deserialize<SubjectPublicKeyInfo>(
                inputData,
                AsnEncodingRules.DER,
                out _);

            
            Assert.Equal("1.2.840.10045.2.1", spki.AlgorithmIdentifier.Algorithm.Value);
            Assert.Equal(PublicKeyValue, spki.PublicKey.ByteArrayToHex());

            AsnReader reader = new AsnReader(spki.AlgorithmIdentifier.Parameters, AsnEncodingRules.DER);
            string curveOid = reader.ReadObjectIdentifierAsString();
            Assert.False(reader.HasData, "reader.HasData");
            Assert.Equal("1.2.840.10045.3.1.7", curveOid);
        }
    }

    // RFC 3280 / ITU-T X.509
    [StructLayout(LayoutKind.Sequential)]
    internal struct AlgorithmIdentifier
    {
        public Oid Algorithm;
        [AnyValue]
        public byte[] Parameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SubjectPublicKeyInfo
    {
        public AlgorithmIdentifier AlgorithmIdentifier;
        [BitString]
        public byte[] PublicKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class AllTheSimpleThings
    {
        private bool _bool;
        private sbyte _sbyte;
        private byte _byte;
        private short _short;
        private ushort _ushort;
        private int _int;
        private uint _uint;
        private long _long;
        private ulong _ulong;
        [Integer]
        private byte[] _bigInt;
        [BitString]
        private byte[] _bitString;
        [OctetString]
        private byte[] _octetString;
        [AnyValue]
        private byte[] _null;
        private Oid _oidNoName;
        [ObjectIdentifier(PopulateFriendlyName = true)]
        private Oid _oid;
        [ObjectIdentifier]
        private string _oidString;
        private UniversalTagNumber _nonFlagsEnum;
        [UTF8String]
        private string _utf8String;
        [IA5String]
        private string _ia5String;
        [BMPString]
        private string _bmpString;
        private bool[] _bools;
        [SetOf]
        private int[] _ints;
        //private byte[] _something;
        //private byte[] _openDrain;

        public bool NotBool => !_bool;
        public sbyte SByte => _sbyte;
        public byte Byte => _byte;
        public short Short => _short;
        public ushort UShort => _ushort;
        public int Int => _int;
        public uint UInt => _uint;
        public long Long => _long;
        public ulong ULong => _ulong;
        public ReadOnlySpan<byte> BigIntBytes => _bigInt;
        public ReadOnlySpan<byte> BitStringBytes => _bitString;
        public ReadOnlySpan<byte> OctetStringBytes => _octetString;
        public ReadOnlySpan<byte> Null => _null;
        public Oid UnattrOid => _oidNoName;
        public Oid WithName => _oid;
        public string OidString => _oidString;
        public UniversalTagNumber LinearEnum => _nonFlagsEnum;
        public string Utf8Encoded => _utf8String;
        public string Ia5Encoded => _ia5String;
        public string BmpEncoded => _bmpString;
        public bool[] Bools => _bools;
        public int[] Ints => _ints;
    }
}
