// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests
{
    public static class TimestampTokenInfoTests
    {
        [Fact]
        public static void CreateFromParameters()
        {
            Oid policyId = new Oid("2.16.840.1.113733.1.7.23.3", "2.16.840.1.113733.1.7.23.3");
            Oid hashAlgorithmOid = new Oid(Oids.Sha256);
            byte[] messageHash =
                "315F5BDB76D078C43B8AC0064E4A0164612B1FCE77C869345BFC94C75894EDD3".HexToByteArray();
            byte[] serial = "6C77B12D5FCF9F6DC1D4A481E935F446FBA376C4".HexToByteArray();
            DateTimeOffset timestamp = new DateTimeOffset(2017, 10, 10, 15, 8, 52, TimeSpan.FromHours(-7));
            long accuracyMicrosec = 30 * 1000 * 1000;

            byte[] tsaNameBytes = (
                "A48183308180310B3009060355040613025553311D301B060355040A13145379" +
                "6D616E74656320436F72706F726174696F6E311F301D060355040B131653796D" +
                "616E746563205472757374204E6574776F726B3131302F060355040313285379" +
                "6D616E746563205348413235362054696D655374616D70696E67205369676E65" +
                "72202D204732").HexToByteArray();

            var tokenInfo = new Rfc3161TimestampTokenInfo(
                policyId,
                hashAlgorithmOid,
                messageHash,
                serial,
                timestamp,
                accuracyMicrosec,
                tsaName: tsaNameBytes);

            const string ExpectedHex =
                "3081F8020101060B6086480186F845010717033031300D060960864801650304" +
                "020105000420315F5BDB76D078C43B8AC0064E4A0164612B1FCE77C869345BFC" +
                "94C75894EDD302146C77B12D5FCF9F6DC1D4A481E935F446FBA376C4180F3230" +
                "3137313031303232303835325A300302011EA08186A48183308180310B300906" +
                "0355040613025553311D301B060355040A131453796D616E74656320436F7270" +
                "6F726174696F6E311F301D060355040B131653796D616E746563205472757374" +
                "204E6574776F726B3131302F0603550403132853796D616E7465632053484132" +
                "35362054696D655374616D70696E67205369676E6572202D204732";

            Assert.Equal(ExpectedHex, tokenInfo.RawData.ByteArrayToHex());

            Assert.NotSame(policyId, tokenInfo.PolicyId);
            Assert.Equal(policyId.Value, tokenInfo.PolicyId.Value);

            Assert.NotSame(hashAlgorithmOid, tokenInfo.HashAlgorithmId);
            Assert.Equal(hashAlgorithmOid.Value, tokenInfo.HashAlgorithmId.Value);
            // FriendlyName should be set for SHA-2-256
            Assert.NotEqual(tokenInfo.HashAlgorithmId.Value, tokenInfo.HashAlgorithmId.FriendlyName);

            Assert.Equal(timestamp, tokenInfo.Timestamp);
            Assert.Equal(TimeSpan.Zero, tokenInfo.Timestamp.Offset);

            Assert.Equal(messageHash.ByteArrayToHex(), tokenInfo.GetMessageHash().ByteArrayToHex());
            // Detached from the original data
            messageHash[0] ^= 0xFF;
            Assert.NotEqual(messageHash.ByteArrayToHex(), tokenInfo.GetMessageHash().ByteArrayToHex());

            Assert.Equal(serial.ByteArrayToHex(), tokenInfo.GetSerialNumber().ByteArrayToHex());
            // Detached from the original data
            serial[1] ^= 0xFF;
            Assert.NotEqual(serial.ByteArrayToHex(), tokenInfo.GetSerialNumber().ByteArrayToHex());

            Assert.Equal(accuracyMicrosec, tokenInfo.AccuracyInMicroseconds);

            ReadOnlyMemory<byte>? nameFromToken = tokenInfo.GetTimestampAuthorityName();
            Assert.True(nameFromToken.HasValue);
            Assert.Equal(tsaNameBytes.ByteArrayToHex(), nameFromToken.Value.ByteArrayToHex());
            // Detached from the original data
            tsaNameBytes[5] ^= 0xFF;
            Assert.NotEqual(tsaNameBytes.ByteArrayToHex(), nameFromToken.Value.ByteArrayToHex());

            // Defaults
            Assert.Equal(1, tokenInfo.Version);
            Assert.False(tokenInfo.IsOrdering);
            Assert.False(tokenInfo.HasExtensions);
            Assert.NotNull(tokenInfo.GetExtensions());
            Assert.Equal(0, tokenInfo.GetExtensions().Count);
            Assert.False(tokenInfo.GetNonce().HasValue);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public static void CreateFromValue(bool viaTry)
        {
            const string InputHex =
                "3081F8020101060B6086480186F845010717033031300D060960864801650304" +
                "020105000420315F5BDB76D078C43B8AC0064E4A0164612B1FCE77C869345BFC" +
                "94C75894EDD302146C77B12D5FCF9F6DC1D4A481E935F446FBA376C4180F3230" +
                "3137313031303232303835325A300302011EA08186A48183308180310B300906" +
                "0355040613025553311D301B060355040A131453796D616E74656320436F7270" +
                "6F726174696F6E311F301D060355040B131653796D616E746563205472757374" +
                "204E6574776F726B3131302F0603550403132853796D616E7465632053484132" +
                "35362054696D655374616D70696E67205369676E6572202D204732";

            byte[] inputData = InputHex.HexToByteArray();

            Rfc3161TimestampTokenInfo tokenInfo;

            if (viaTry)
            {
                Assert.True(Rfc3161TimestampTokenInfo.TryParse(inputData, out int bytesRead, out tokenInfo));
                Assert.Equal(inputData.Length, bytesRead);
                Assert.NotNull(tokenInfo);
            }
            else
            {
                tokenInfo = new Rfc3161TimestampTokenInfo(inputData);
            }

            Oid policyId = new Oid("2.16.840.1.113733.1.7.23.3", "2.16.840.1.113733.1.7.23.3");
            Oid hashAlgorithmOid = new Oid(Oids.Sha256);
            byte[] messageHash =
                "315F5BDB76D078C43B8AC0064E4A0164612B1FCE77C869345BFC94C75894EDD3".HexToByteArray();
            byte[] serial = "6C77B12D5FCF9F6DC1D4A481E935F446FBA376C4".HexToByteArray();
            DateTimeOffset timestamp = new DateTimeOffset(2017, 10, 10, 15, 8, 52, TimeSpan.FromHours(-7));
            long accuracyMicrosec = 30 * 1000 * 1000;

            byte[] tsaNameBytes = (
                "A48183308180310B3009060355040613025553311D301B060355040A13145379" +
                "6D616E74656320436F72706F726174696F6E311F301D060355040B131653796D" +
                "616E746563205472757374204E6574776F726B3131302F060355040313285379" +
                "6D616E746563205348413235362054696D655374616D70696E67205369676E65" +
                "72202D204732").HexToByteArray();

            Assert.Equal(1, tokenInfo.Version);

            Assert.Equal(policyId.Value, tokenInfo.PolicyId.Value);

            Assert.Equal(hashAlgorithmOid.Value, tokenInfo.HashAlgorithmId.Value);
            // FriendlyName should be set for SHA-2-256
            Assert.NotEqual(tokenInfo.HashAlgorithmId.Value, tokenInfo.HashAlgorithmId.FriendlyName);

            Assert.Equal(messageHash.ByteArrayToHex(), tokenInfo.GetMessageHash().ByteArrayToHex());

            Assert.Equal(serial.ByteArrayToHex(), tokenInfo.GetSerialNumber().ByteArrayToHex());

            Assert.Equal(timestamp, tokenInfo.Timestamp);
            Assert.Equal(TimeSpan.Zero, tokenInfo.Timestamp.Offset);

            Assert.Equal(accuracyMicrosec, tokenInfo.AccuracyInMicroseconds);

            Assert.False(tokenInfo.IsOrdering);

            Assert.False(tokenInfo.GetNonce().HasValue);

            ReadOnlyMemory<byte>? tsaNameFromToken = tokenInfo.GetTimestampAuthorityName();
            Assert.True(tsaNameFromToken.HasValue);
            Assert.Equal(tsaNameBytes.ByteArrayToHex(), tsaNameFromToken.Value.ByteArrayToHex());

            Assert.False(tokenInfo.HasExtensions);
            Assert.NotNull(tokenInfo.GetExtensions());
            Assert.Equal(0, tokenInfo.GetExtensions().Count);
        }

        [Fact]
        public static void TryParse_LongerThanNeeded()
        {
            const string ExcessHex = "00010203040506070809";

            const string InputHex =
                "3081F8020101060B6086480186F845010717033031300D060960864801650304" +
                "020105000420315F5BDB76D078C43B8AC0064E4A0164612B1FCE77C869345BFC" +
                "94C75894EDD302146C77B12D5FCF9F6DC1D4A481E935F446FBA376C4180F3230" +
                "3137313031303232303835325A300302011EA08186A48183308180310B300906" +
                "0355040613025553311D301B060355040A131453796D616E74656320436F7270" +
                "6F726174696F6E311F301D060355040B131653796D616E746563205472757374" +
                "204E6574776F726B3131302F0603550403132853796D616E7465632053484132" +
                "35362054696D655374616D70696E67205369676E6572202D204732" + ExcessHex;

            byte[] inputData = InputHex.HexToByteArray();

            Rfc3161TimestampTokenInfo tokenInfo;
            Assert.True(Rfc3161TimestampTokenInfo.TryParse(inputData, out int bytesRead, out tokenInfo));
            Assert.Equal(inputData.Length - ExcessHex.Length / 2, bytesRead);

            Oid policyId = new Oid("2.16.840.1.113733.1.7.23.3", "2.16.840.1.113733.1.7.23.3");
            Oid hashAlgorithmOid = new Oid(Oids.Sha256);
            byte[] messageHash =
                "315F5BDB76D078C43B8AC0064E4A0164612B1FCE77C869345BFC94C75894EDD3".HexToByteArray();
            byte[] serial = "6C77B12D5FCF9F6DC1D4A481E935F446FBA376C4".HexToByteArray();
            DateTimeOffset timestamp = new DateTimeOffset(2017, 10, 10, 15, 8, 52, TimeSpan.FromHours(-7));
            long accuracyMicrosec = 30 * 1000 * 1000;

            byte[] tsaNameBytes = (
                "A48183308180310B3009060355040613025553311D301B060355040A13145379" +
                "6D616E74656320436F72706F726174696F6E311F301D060355040B131653796D" +
                "616E746563205472757374204E6574776F726B3131302F060355040313285379" +
                "6D616E746563205348413235362054696D655374616D70696E67205369676E65" +
                "72202D204732").HexToByteArray();

            Assert.Equal(1, tokenInfo.Version);

            Assert.Equal(policyId.Value, tokenInfo.PolicyId.Value);

            Assert.Equal(hashAlgorithmOid.Value, tokenInfo.HashAlgorithmId.Value);
            // FriendlyName should be set for SHA-2-256
            Assert.NotEqual(tokenInfo.HashAlgorithmId.Value, tokenInfo.HashAlgorithmId.FriendlyName);

            Assert.Equal(messageHash.ByteArrayToHex(), tokenInfo.GetMessageHash().ByteArrayToHex());

            Assert.Equal(serial.ByteArrayToHex(), tokenInfo.GetSerialNumber().ByteArrayToHex());

            Assert.Equal(timestamp, tokenInfo.Timestamp);
            Assert.Equal(TimeSpan.Zero, tokenInfo.Timestamp.Offset);

            Assert.Equal(accuracyMicrosec, tokenInfo.AccuracyInMicroseconds);

            Assert.False(tokenInfo.IsOrdering);

            Assert.False(tokenInfo.GetNonce().HasValue);

            ReadOnlyMemory<byte>? tsaNameFromToken = tokenInfo.GetTimestampAuthorityName();
            Assert.True(tsaNameFromToken.HasValue);
            Assert.Equal(tsaNameBytes.ByteArrayToHex(), tsaNameFromToken.Value.ByteArrayToHex());

            Assert.False(tokenInfo.HasExtensions);
            Assert.NotNull(tokenInfo.GetExtensions());
            Assert.Equal(0, tokenInfo.GetExtensions().Count);
        }

        [Fact]
        public static void TryParse_Invalid()
        {
            const string InputHex =
                "3081F8020101060B6086480186F845010717033031300D060960864801650304" +
                "020105000420315F5BDB76D078C43B8AC0064E4A0164612B1FCE77C869345BFC" +
                "94C75894EDD302146C77B12D5FCF9F6DC1D4A481E935F446FBA376C4180F3230" +
                "3137313031303232303835325A300302011EA08186A48183308180310B300906" +
                "0355040613025553311D301B060355040A131453796D616E74656320436F7270" +
                "6F726174696F6E311F301D060355040B131653796D616E746563205472757374" +
                "204E6574776F726B3131302F0603550403132853796D616E7465632053484132" +
                "35362054696D655374616D70696E67205369676E6572202D204732";

            byte[] inputData = InputHex.HexToByteArray();

            Assert.False(
                Rfc3161TimestampTokenInfo.TryParse(
                    new ReadOnlyMemory<byte>(inputData, 0, inputData.Length - 1),
                    out int bytesRead,
                    out Rfc3161TimestampTokenInfo tokenInfo));

            Assert.Equal(0, bytesRead);
            Assert.Null(tokenInfo);
        }

        [Fact]
        public static void Ctor_InvalidData_ThrowsOnRead()
        {
            const string InputHex =
                "3081F8020101060B6086480186F845010717033031300D060960864801650304" +
                "020105000420315F5BDB76D078C43B8AC0064E4A0164612B1FCE77C869345BFC" +
                "94C75894EDD302146C77B12D5FCF9F6DC1D4A481E935F446FBA376C4180F3230" +
                "3137313031303232303835325A300302011EA08186A48183308180310B300906" +
                "0355040613025553311D301B060355040A131453796D616E74656320436F7270" +
                "6F726174696F6E311F301D060355040B131653796D616E746563205472757374" +
                "204E6574776F726B3131302F0603550403132853796D616E7465632053484132" +
                "35362054696D655374616D70696E67205369676E6572202D2047";
            // Missing a final "32";

            byte[] inputData = InputHex.HexToByteArray();
            var tokenInfo = new Rfc3161TimestampTokenInfo(inputData);

            Assert.Throws<CryptographicException>(() => tokenInfo.Version);
            Assert.Throws<CryptographicException>(() => tokenInfo.PolicyId);
            Assert.Throws<CryptographicException>(() => tokenInfo.HashAlgorithmId);
            Assert.Throws<CryptographicException>(() => tokenInfo.GetMessageHash());
            Assert.Throws<CryptographicException>(() => tokenInfo.GetSerialNumber());
            Assert.Throws<CryptographicException>(() => tokenInfo.AccuracyInMicroseconds);
            Assert.Throws<CryptographicException>(() => tokenInfo.Timestamp);
            Assert.Throws<CryptographicException>(() => tokenInfo.GetNonce());
            Assert.Throws<CryptographicException>(() => tokenInfo.GetTimestampAuthorityName());
            Assert.Throws<CryptographicException>(() => tokenInfo.HasExtensions);
            Assert.Throws<CryptographicException>(() => tokenInfo.GetExtensions());
        }

        [Fact]
        public static void BuilderCtor_PolicyIdRequired()
        {
            AssertExtensions.Throws<ArgumentNullException>(
                "policyId",
                () => new Rfc3161TimestampTokenInfo(null, null, default, default, default));
        }

        [Fact]
        public static void BuilderCtor_HashAlgorithmIdRequired()
        {
            Oid policyId = new Oid("0.0", "0.0");

            AssertExtensions.Throws<ArgumentNullException>(
                "hashAlgorithmId",
                () => new Rfc3161TimestampTokenInfo(policyId, null, default, default, default));
        }

        [Fact]
        public static void BuilderCtor_TsaNameOptional()
        {
            Oid policyId = new Oid("0.0", "0.0");
            Oid hashAlgorithmId = new Oid(Oids.Sha256);

            var tokenInfo = new Rfc3161TimestampTokenInfo(
                policyId,
                hashAlgorithmId,
                new byte[256 / 8],
                new byte[] { 1 },
                DateTimeOffset.UtcNow);

            tokenInfo = new Rfc3161TimestampTokenInfo(tokenInfo.RawData);

            Assert.False(tokenInfo.GetTimestampAuthorityName().HasValue);
        }

        [Fact]
        public static void BuilderCtor_AccuracyOptional()
        {
            Oid policyId = new Oid("0.0", "0.0");
            Oid hashAlgorithmId = new Oid(Oids.Sha256);

            var tokenInfo = new Rfc3161TimestampTokenInfo(
                policyId,
                hashAlgorithmId,
                new byte[256 / 8],
                new byte[] { 2 },
                DateTimeOffset.UtcNow);

            tokenInfo = new Rfc3161TimestampTokenInfo(tokenInfo.RawData);

            Assert.False(tokenInfo.AccuracyInMicroseconds.HasValue);
        }

        [Fact]
        public static void TsaName_SameDataSecondInvocation()
        {
            const string InputHex =
                "3081F8020101060B6086480186F845010717033031300D060960864801650304" +
                "020105000420315F5BDB76D078C43B8AC0064E4A0164612B1FCE77C869345BFC" +
                "94C75894EDD302146C77B12D5FCF9F6DC1D4A481E935F446FBA376C4180F3230" +
                "3137313031303232303835325A300302011EA08186A48183308180310B300906" +
                "0355040613025553311D301B060355040A131453796D616E74656320436F7270" +
                "6F726174696F6E311F301D060355040B131653796D616E746563205472757374" +
                "204E6574776F726B3131302F0603550403132853796D616E7465632053484132" +
                "35362054696D655374616D70696E67205369676E6572202D204732";

            var tokenInfo = new Rfc3161TimestampTokenInfo(InputHex.HexToByteArray());

            ReadOnlyMemory<byte>? tsaName = tokenInfo.GetTimestampAuthorityName();
            Assert.True(tsaName.HasValue, "tsaName.HasValue");
            ReadOnlyMemory<byte> tsaName1 = tsaName.Value;
            ReadOnlyMemory<byte> tsaName2 = tokenInfo.GetTimestampAuthorityName().Value;

            Assert.Equal(tsaName1.Length, tsaName2.Length);

            Assert.True(
                Unsafe.AreSame(
                    ref tsaName1.Span.DangerousGetPinnableReference(),
                    ref tsaName2.Span.DangerousGetPinnableReference()),
                "Second call to GetTimestampAuthorityName is over the same memory");
        }

        [Fact]
        public static void ExtensionsRoundtrips()
        {
            Oid policyId = new Oid("0.0", "0.0");
            Oid hashAlgorithmId = new Oid(Oids.Sha256);

            byte[] extensionValue = { 3, 1, 4, 1, 5, 9, 2, 7, 5, 8 };
            
            var tokenInfo = new Rfc3161TimestampTokenInfo(
                policyId,
                hashAlgorithmId,
                new byte[256 / 8],
                new byte[] { 3 },
                DateTimeOffset.UtcNow,
                extensions: new X509ExtensionCollection
                {
                    new X509Extension(new Oid("0.0.0", "0.0.0"), extensionValue, true),
                });

            tokenInfo = new Rfc3161TimestampTokenInfo(tokenInfo.RawData);

            Assert.True(tokenInfo.HasExtensions);
            X509ExtensionCollection extensions = tokenInfo.GetExtensions();

            Assert.Equal(1, extensions.Count);
            X509Extension extension = extensions[0];
            Assert.NotNull(extension);
            Assert.Equal("0.0.0", extension.Oid.Value);
            Assert.True(extension.Critical, "extension.Critical");
            Assert.Equal(extensionValue.ByteArrayToHex(), extension.RawData.ByteArrayToHex());
        }

        [Fact]
        public static void BuilderCtor_IsOrdering_Roundtrips()
        {
            Oid policyId = new Oid("0.0", "0.0");
            Oid hashAlgorithmId = new Oid(Oids.Sha256);

            var tokenInfo = new Rfc3161TimestampTokenInfo(
                policyId,
                hashAlgorithmId,
                new byte[256 / 8],
                new byte[] { 7 },
                DateTimeOffset.UtcNow,
                isOrdering: true);

            tokenInfo = new Rfc3161TimestampTokenInfo(tokenInfo.RawData);
            Assert.True(tokenInfo.IsOrdering, "tokenInfo.IsOrdering");
        }

        [Fact]
        public static void CopyFrom_ResetsState()
        {
            Oid policyId1 = new Oid("0.0", "0.0");
            Oid hashAlgorithmId1 = new Oid(Oids.Sha256);
            Oid policyId2 = new Oid("1.1", "1.1");
            Oid hashAlgorithmId2 = new Oid(Oids.Sha384);

            var tokenInfo1 = new Rfc3161TimestampTokenInfo(
                policyId1,
                hashAlgorithmId1,
                new byte[256 / 8],
                new byte[] { 4 },
                DateTimeOffset.UnixEpoch);

            Assert.Equal(DateTimeOffset.UnixEpoch, tokenInfo1.Timestamp);
            Assert.False(tokenInfo1.AccuracyInMicroseconds.HasValue);

            DateTimeOffset marker = new DateTimeOffset(2017, 12, 18, 17, 5, 34, TimeSpan.Zero);

            var tokenInfo2 = new Rfc3161TimestampTokenInfo(
                policyId2,
                hashAlgorithmId2,
                new byte[384 / 8],
                new byte[] { 5 },
                marker,
                accuracyInMicroseconds: 847,
                nonce: new byte[] { 65, 69, 73, 79, 85, 89 },
                tsaName: null,
                extensions: null);

            AsnEncodedData untypedData = new AsnEncodedData(tokenInfo2.Oid, tokenInfo2.RawData);
            tokenInfo1.CopyFrom(untypedData);

            Assert.Equal(marker, tokenInfo1.Timestamp);
            Assert.True(tokenInfo1.AccuracyInMicroseconds.HasValue);
            Assert.True(tokenInfo1.GetNonce().HasValue);
            Assert.Equal("AEIOUY", Text.Encoding.ASCII.GetString(tokenInfo1.GetNonce().Value.Span));
            Assert.Equal(847, tokenInfo1.AccuracyInMicroseconds);
            Assert.Equal(Oids.Sha384, tokenInfo1.HashAlgorithmId.Value);
            Assert.Equal(policyId2.Value, tokenInfo1.PolicyId.Value);
            Assert.Equal(384 / 8, tokenInfo1.GetMessageHash().Length);
        }

        [Fact]
        public static void BuilderCtor_Timestamp_KeepsSubSeconds()
        {
            // RFC 3161 says that the genTime value should omit fractions "when there is no need"
            //
            // We leave the trimming up to the caller, because there are multiple positions for
            // the accuracy+precision position.
            DateTimeOffset marker = new DateTimeOffset(2017, 12, 18, 17, 5, 34, TimeSpan.Zero);
            DateTimeOffset experiment = marker + TimeSpan.FromMilliseconds(17);

            Assert.NotEqual(marker, experiment);

            Oid policyId1 = new Oid("0.0", "0.0");
            Oid hashAlgorithmId1 = new Oid(Oids.Sha256);

            var tokenInfo = new Rfc3161TimestampTokenInfo(
                policyId1,
                hashAlgorithmId1,
                new byte[256 / 8],
                new byte[] { 6 },
                experiment);

            Assert.Equal(experiment, tokenInfo.Timestamp);
        }

        [Fact]
        public static void CreateFromValue_SubSecondAccuracy()
        {
            const string InputHex =
                "3082019802010106042A0304013041300D060960864801650304020205000430" +
                "9111E404B85D1F088C23DBE654943F30B103B6CBFE01898A1F7701A23B055E79" +
                "C27AEE38BC44CC0F212DBAC0EBE92C580203064F641816323031373132313831" +
                "37333431362E3830303831325A300A020101800201F48101640101FF02090096" +
                "31D170EA3B92D4A0820111A482010D308201093111300F060355040A13084672" +
                "656520545341310C300A060355040B130354534131763074060355040D136D54" +
                "686973206365727469666963617465206469676974616C6C79207369676E7320" +
                "646F63756D656E747320616E642074696D65207374616D702072657175657374" +
                "73206D616465207573696E672074686520667265657473612E6F7267206F6E6C" +
                "696E65207365727669636573311830160603550403130F7777772E6672656574" +
                "73612E6F72673122302006092A864886F70D0109011613627573696C657A6173" +
                "40676D61696C2E636F6D3112301006035504071309577565727A62757267310B" +
                "3009060355040613024445310F300D0603550408130642617965726E";

            byte[] inputData = InputHex.HexToByteArray();

            var tokenInfo = new Rfc3161TimestampTokenInfo(inputData);

            Assert.Equal(1, tokenInfo.Version);
            Assert.Equal("1.2.3.4.1", tokenInfo.PolicyId.Value);
            Assert.Equal(Oids.Sha384, tokenInfo.HashAlgorithmId.Value);

            Assert.Equal(
                "9111E404B85D1F088C23DBE654943F30B103B6CBFE01898A1F7701A23B055E79C27AEE38BC44CC0F212DBAC0EBE92C58",
                tokenInfo.GetMessageHash().ByteArrayToHex());

            Assert.Equal(
                ((BigInteger)413540).ToByteArray(isBigEndian: true).ByteArrayToHex(),
                tokenInfo.GetSerialNumber().ByteArrayToHex());

            Assert.Equal(
                1 * 1_000_000 + 0x1F4 * 1000 + 0x64,
                tokenInfo.AccuracyInMicroseconds);

            Assert.True(tokenInfo.IsOrdering);
            Assert.Equal("009631D170EA3B92D4", tokenInfo.GetNonce().Value.ByteArrayToHex());
            Assert.Equal(273, tokenInfo.GetTimestampAuthorityName().Value.Length);
        }

        [Theory]
        [InlineData("No accuracy", "", true, null)]
        [InlineData("MicroSeconds = 0", "3003810100", false, null)]
        [InlineData("MicroSeconds = 1", "3003810101", true, 1L)]
        [InlineData("MicroSeconds = 999", "3004810203E7", true, 999L)]
        [InlineData("MicroSeconds = 1000", "3004810203E8", false, null)]
        [InlineData("MilliSeconds = 0", "3003800100", false, null)]
        [InlineData("MilliSeconds = 1", "3003800101", true, 1000L)]
        [InlineData("MilliSeconds = 999", "3004800203E7", true, 999000L)]
        [InlineData("MilliSeconds = 1000", "3004800203E8", false, null)]
        [InlineData("Seconds = 0", "3003020100", true, 0L)]
        [InlineData("Seconds = -1", "30030201FF", false, null)]
        public static void Accuracy_Bounds_ParsesAsExpected(
            string description,
            string accuracyHex,
            bool shouldParse,
            long? expectedTotalMicroseconds)
        {
            string inputHex =
                "305A0201010601003031300D0609608648016503040201050004200000000000" +
                "0000000000000000000000000000000000000000000000000000000201081817" +
                "32303137313231383138313235342E373438363336345A" + accuracyHex;

            byte[] inputData = inputHex.HexToByteArray();
            inputData[1] = checked((byte)(0x55 + accuracyHex.Length / 2));

            if (shouldParse)
            {
                int bytesRead;
                Rfc3161TimestampTokenInfo tokenInfo;

                Assert.True(Rfc3161TimestampTokenInfo.TryParse(inputData, out bytesRead, out tokenInfo));
                Assert.Equal(inputData.Length, bytesRead);
                Assert.NotNull(tokenInfo);
                Assert.Equal(expectedTotalMicroseconds, tokenInfo.AccuracyInMicroseconds);
            }
            else
            {
                Assert.False(Rfc3161TimestampTokenInfo.TryParse(inputData, out _, out _));
            }
        }
    }
}
