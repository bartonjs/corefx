// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.ObjectModel;
using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests.Pkcs12
{
    public static class Pkcs12InfoTests
    {
        [Fact]
        public static void ReadEmptyPfx()
        {
            Pkcs12Info info =
                Pkcs12Info.Decode(Pkcs12Documents.EmptyPfx, out int bytesRead, skipCopy: true);

            Assert.Equal(Pkcs12Documents.EmptyPfx.Length, bytesRead);
            Assert.Equal(Pkcs12Info.IntegrityMode.Password, info.DataIntegrityMode);

            Assert.False(info.VerifyMac("hello"), "Wrong password");
            Assert.True(info.VerifyMac(ReadOnlySpan<char>.Empty), "null password");
            Assert.False(info.VerifyMac(""), "empty password");
            Assert.False(info.VerifyMac("hello".AsSpan(5)), "sliced out");
            Assert.False(info.VerifyMac("hello".AsSpan(0, 0)), "zero-sliced");
            Assert.False(info.VerifyMac(new char[0]), "empty array");
            Assert.False(info.VerifyMac((new char[1]).AsSpan(1)), "sliced out array");
            Assert.False(info.VerifyMac((new char[1]).AsSpan(0, 0)), "zero-sliced array");

            ReadOnlyCollection<Pkcs12SafeContents> safes = info.AuthenticatedSafe;
            Assert.Equal(0, safes.Count);
        }
    }
}
