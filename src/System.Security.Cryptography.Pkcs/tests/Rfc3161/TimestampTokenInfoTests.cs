// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

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
    }
}
