// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;
using Test.Cryptography;
using Xunit;

using PublicEncodingRules = System.Security.Cryptography.Tests.Asn1.Asn1ReaderTests.PublicEncodingRules;

namespace System.Security.Cryptography.Tests.Asn1
{
    public static class X509DeserializeTests
    {
        [Fact]
        public static void ReadMicrosoftDotCom()
        {
            byte[] buf = Convert.FromBase64String(MicrosoftDotComBase64);

            Certificate cert = AsnSerializer.Deserialize<Certificate>(
                buf,
                AsnEncodingRules.DER,
                out _);

            Assert.Equal("1.2.840.113549.1.1.11", cert.SignatureAlgorithm.Algorithm.Value);
            Assert.False(true, "Test passed");
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct Certificate
        {
            public TbsCertificate TbsCertificate;
            public AlgorithmIdentifier SignatureAlgorithm;
            [BitString]
            public byte[] Signature;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct TbsCertificate
        {
            [TagOverride(0)]
            [DefaultValue(0x01)]
            public int Version;

            [Integer]
            public byte[] SerialNumber;

            public AlgorithmIdentifier Signature;

            public Name Issuer;

            public Validity Validity;

            public Name Subject;

            public SubjectPublicKeyInfo SubjectPublicKeyInfo;

            [TagOverride(1), BitString, OptionalValue]
            public byte[] IssuerUniqueId;

            [TagOverride(2), BitString, OptionalValue]
            public byte[] SubjectUniqueId;

            [TagOverride(3), OptionalValue]
            public Extension[] Extensions;
        }

        [Choice]
        [StructLayout(LayoutKind.Sequential)]
        public struct Name
        {
            public RelativeDistinguishedName[] RdnSequence;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RelativeDistinguishedName
        {
            [SetOf]
            public AttributeTypeAndValue[] Values;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct AttributeTypeAndValue
        {
            [ObjectIdentifier]
            public string AttributeType;

            public AttributeValue Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct AttributeValue
        {
            [AnyValue]
            public byte[] Any;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct Extension
        {
            [ObjectIdentifier]
            public string ExtnId;

            [OptionalValue]
            [DefaultValue(0x00)]
            public bool Critical;

            [OctetString]
            public byte[] ExtnValue;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Validity
        {
            public Time NotBefore;
            public Time NotAfter;
        }

        [Choice]
        [StructLayout(LayoutKind.Sequential)]
        public struct Time
        {
            public DateTimeOffset UtcTime;
            public DateTimeOffset GeneralTime;
        }

        private const string MicrosoftDotComBase64 =
            @"
MIIFlDCCBHygAwIBAgIQPfcMXZkD+NiGi5uMzyDfaTANBgkqhkiG9w0BAQsFADB3
MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAd
BgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxKDAmBgNVBAMTH1N5bWFudGVj
IENsYXNzIDMgRVYgU1NMIENBIC0gRzMwHhcNMTQxMDE1MDAwMDAwWhcNMTYxMDE1
MjM1OTU5WjCCAQ8xEzARBgsrBgEEAYI3PAIBAxMCVVMxGzAZBgsrBgEEAYI3PAIB
AgwKV2FzaGluZ3RvbjEdMBsGA1UEDxMUUHJpdmF0ZSBPcmdhbml6YXRpb24xEjAQ
BgNVBAUTCTYwMDQxMzQ4NTELMAkGA1UEBhMCVVMxDjAMBgNVBBEMBTk4MDUyMRMw
EQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdSZWRtb25kMRgwFgYDVQQJDA8x
IE1pY3Jvc29mdCBXYXkxHjAcBgNVBAoMFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEO
MAwGA1UECwwFTVNDT00xGjAYBgNVBAMMEXd3dy5taWNyb3NvZnQuY29tMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApGhh+p1dt2NjO/WmTvbnwsI2f0jS
1GZDoi38/Msk5YoU0PBr3JVkN/Kla6S+9wujYb8SlkoNZlr9hLD3SUyPpKvF/KLg
F8BheK7yza0bXxjpl6FLllwHTo9WSXBgcnawBYOTIkD+bi3QEwJvmuE9fJHMB8Th
6Oh3N9wG7ytXW4nWLv5GhZ+CVaEjaSpwbGgSLU2v4RyyBaez3gblU/e5X5eO+GAa
jfgZvzIEC9+SoN4N8mm0UUKC4XrGmTToRApIq50fXfiaUCzvbf2+eQBFvUXgyU5c
qK3XagE+nJeEQPyKniqaSUCyRggZw+MCqpyfNVrXVMhtPtd92qPaE4ELTQIDAQAB
o4IBgDCCAXwwMQYDVR0RBCowKIIRd3d3Lm1pY3Jvc29mdC5jb22CE3d3d3FhLm1p
Y3Jvc29mdC5jb20wCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYw
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwYw
TDAjBggrBgEFBQcCARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUH
AgIwGRoXaHR0cHM6Ly9kLnN5bWNiLmNvbS9ycGEwHwYDVR0jBBgwFoAUAVmr5906
C1mmZGPWzyAHV9WR52owKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3NyLnN5bWNi
LmNvbS9zci5jcmwwVwYIKwYBBQUHAQEESzBJMB8GCCsGAQUFBzABhhNodHRwOi8v
c3Iuc3ltY2QuY29tMCYGCCsGAQUFBzAChhpodHRwOi8vc3Iuc3ltY2IuY29tL3Ny
LmNydDANBgkqhkiG9w0BAQsFAAOCAQEAFfhQW2J+1/n5ZwcJfpOlHnp+BaPUIKXC
WOx6HP4YQ+wgrPcoqvp6GhvCIqfNv0r5CqJt7rOQnAs/tceAcNrj1kW/z4QKSj/d
mIx7Mwi/5Os/1mxFZB6WyjNS2+KutEiKZKnF+5aTK6cAWc6SvSeLQSmf0hNHG9gW
X5JCha4+zWZscDiF3KZdJNpm06+uOZaFIZlaTDmMffON+oKiA3LxPUpWrbIbWCJU
mRgBVke1+KwTHMXrJFNNFyvGAhioi2W89xx/OIzj4O9pe0IDcgSDu1eURVtZfYDU
jNOh1zy7xgnAWHZ9H/BgpgnX49QxcHmvDNCopJJRqxKRV/mJSgNkhw==
";
    }
}
