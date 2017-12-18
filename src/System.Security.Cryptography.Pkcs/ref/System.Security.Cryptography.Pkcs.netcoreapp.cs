// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// ------------------------------------------------------------------------------
// Changes to this file must follow the http://aka.ms/api-review process.
// ------------------------------------------------------------------------------

using System.Security.Cryptography.X509Certificates;

namespace System.Security.Cryptography.Pkcs
{
    public sealed partial class SignerInfo
    {
        public Oid SignatureAlgorithm => throw null;
        public byte[] GetSignature() => throw null;
    }
    public sealed partial class Rfc3161TimestampTokenInfo : AsnEncodedData
    {
        public Rfc3161TimestampTokenInfo(byte[] timestampTokenInfo) { }
        public Rfc3161TimestampTokenInfo(Oid policyId, Oid hashAlgorithmId, ReadOnlyMemory<byte> messageHash, ReadOnlyMemory<byte> serialNumber, DateTimeOffset timestamp, long? accuracyInMicroseconds=null, bool isOrdering=false, ReadOnlyMemory<byte>? nonce=null, ReadOnlyMemory<byte>? tsaName=null, X509ExtensionCollection extensions =null) { throw null; }
        public int Version => throw null;
        public Oid PolicyId=> throw null;
        public Oid HashAlgorithmId => throw null;
        public ReadOnlyMemory<byte> GetMessageHash() { throw null; }
        public ReadOnlyMemory<byte> GetSerialNumber() { throw null; }
        public DateTimeOffset Timestamp => throw null;
        public long? AccuracyInMicroseconds => throw null;
        public bool IsOrdering => throw null;
        public ReadOnlyMemory<byte>? GetNonce() { throw null; }
        public ReadOnlyMemory<byte>? GetTimestampAuthorityName() { throw null; }
        public bool HasExtensions => throw null;
        public X509ExtensionCollection GetExtensions() { throw null; }
        public static bool TryParse(ReadOnlyMemory<byte> source, out int bytesRead, out Rfc3161TimestampTokenInfo timestampTokenInfo) { throw null; }
    }
}
