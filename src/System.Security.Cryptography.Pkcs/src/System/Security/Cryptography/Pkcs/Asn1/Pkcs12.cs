// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography.Pkcs.Asn1
{
    // https://tools.ietf.org/html/rfc7292#section-4
    //
    // PFX ::= SEQUENCE {
    //   version    INTEGER {v3(3)}(v3,...),
    //   authSafe   ContentInfo,
    //   macData    MacData OPTIONAL
    // }
    [StructLayout(LayoutKind.Sequential)]
    internal struct Pfx
    {
        [Integer]
        public byte Version;

        public ContentInfoAsn AuthSafe;

        public MacData? MacData;
    }

    // https://tools.ietf.org/html/rfc7292#section-4
    // 
    // MacData ::= SEQUENCE {
    //   mac        DigestInfo,
    //   macSalt    OCTET STRING,
    //   iterations INTEGER DEFAULT 1
    //   -- Note: The default is for historical reasons and its use is
    //   -- deprecated.
    // }
    [StructLayout(LayoutKind.Sequential)]
    internal struct MacData
    {
        public DigestInfoAsn Mac;

        [OctetString]
        public ReadOnlyMemory<byte> MacSalt;

        [DefaultValue(0x02, 0x01, 0x01)]
        public uint IterationCount;
    }

    // https://tools.ietf.org/html/rfc2313#section-10.1.2
    //
    // DigestInfo ::= SEQUENCE {
    //   digestAlgorithm DigestAlgorithmIdentifier,
    //   digest Digest }
    // 
    // DigestAlgorithmIdentifier ::= AlgorithmIdentifier
    // Digest ::= OCTET STRING
    [StructLayout(LayoutKind.Sequential)]
    internal struct DigestInfoAsn
    {
        public AlgorithmIdentifierAsn DigestAlgorithm;

        [OctetString]
        public ReadOnlyMemory<byte> Digest;
    }
}
