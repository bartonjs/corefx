// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests.Pkcs12
{
    public static class Pkcs12SafeContentsTests
    {
        [Fact]
        public static void StartsInNoConfidentialityMode()
        {
            Pkcs12SafeContents contents = new Pkcs12SafeContents();
            Assert.Equal(Pkcs12SafeContents.ConfidentialityMode.None, contents.DataConfidentialityMode);
        }
    }
}
