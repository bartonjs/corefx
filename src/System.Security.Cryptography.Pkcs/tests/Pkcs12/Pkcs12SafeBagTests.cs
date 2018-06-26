// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Linq;
using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests.Pkcs12
{
    public static class Pkcs12SafeBagTests
    {
        [Fact]
        public static void OidRequired()
        {
            AssertExtensions.Throws<ArgumentNullException>(
                "bagIdValue",
                () => new TestSafeBag(null));
        }

        [Fact]
        public static void OidValidatedLate()
        {
            Pkcs12SafeBag safeBag = new TestSafeBag("potato");
            Assert.ThrowsAny<CryptographicException>(() => safeBag.Encode());
        }

        [Fact]
        public static void OidHasNoNamespaceRequirement()
        {
            Pkcs12SafeBag safeBag = new TestSafeBag(Oids.Aes192);
            byte[] encoded = safeBag.Encode();
            Assert.NotNull(encoded);
        }

        [Fact]
        public static void TryEncodeValueGrows()
        {
            TestSafeBag safeBag = new TestSafeBag(Oids.ContentType);
            byte[] encoded = safeBag.Encode();
            Assert.NotNull(encoded);

            Assert.InRange(safeBag.LastDestinationSize, safeBag.DeniedDestinationSize + 1, int.MaxValue);
        }

        [Fact]
        public static void TryEncodeBoundary()
        {
            TestSafeBag safeBag = new TestSafeBag(Oids.ContentType);
            byte[] encoded = safeBag.Encode();

            byte[] buf = new byte[encoded.Length + 4];
            buf.AsSpan().Fill(0xCA);

            Assert.False(safeBag.TryEncode(buf.AsSpan(0, encoded.Length - 1), out int bytesWritten));
            Assert.Equal(0, bytesWritten);
            Assert.True(buf.All(b => b == 0xCA));
            
            Assert.True(safeBag.TryEncode(buf.AsSpan(1), out bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.Equal(0xCA, buf[0]);
            Assert.Equal(0xCA, buf[bytesWritten + 1]);
            Assert.True(encoded.AsSpan().SequenceEqual(buf.AsSpan(1, bytesWritten)));

            buf.AsSpan().Fill(0xCA);
            Assert.True(safeBag.TryEncode(buf.AsSpan(2, bytesWritten), out bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(buf.AsSpan(2, bytesWritten)));
        }

        [Fact]
        public static void GetBagIdIsFactory()
        {
            Pkcs12SafeBag safeBag = new TestSafeBag(Oids.Aes192);
            Oid firstCall = safeBag.GetBagId();
            Oid secondCall = safeBag.GetBagId();
            Assert.NotSame(firstCall, secondCall);
            Assert.Equal(Oids.Aes192, firstCall.Value);
            Assert.Equal(firstCall.Value, secondCall.Value);

            secondCall.Value = Oids.Cms3DesWrap;
            Assert.NotEqual(firstCall.Value, secondCall.Value);
            Assert.Equal(Oids.Aes192, firstCall.Value);
        }

        [Fact]
        public static void AttributesIsMutable()
        {
            Pkcs12SafeBag safeBag = new TestSafeBag(Oids.Aes192);
            CryptographicAttributeObjectCollection firstCall = safeBag.Attributes;
            Assert.Same(firstCall, safeBag.Attributes);

            Assert.Equal(0, firstCall.Count);
            firstCall.Add(new Pkcs9DocumentDescription("Description"));

            Assert.Equal(1, safeBag.Attributes.Count);
            Assert.Same(firstCall, safeBag.Attributes);
        }

        private class TestSafeBag : Pkcs12SafeBag
        {
            internal int LastDestinationSize = -1;
            internal int DeniedDestinationSize = -1;

            public TestSafeBag(string bagIdValue) : base(bagIdValue)
            {
            }

            protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
            {
                if (destination.Length < 2 || DeniedDestinationSize < 0)
                {
                    DeniedDestinationSize = destination.Length;
                    bytesWritten = 0;
                    return false;
                }

                destination[0] = 0x05;
                destination[1] = 0x00;
                bytesWritten = 2;
                LastDestinationSize = destination.Length;
                return true;
            }
        }
    }
}
