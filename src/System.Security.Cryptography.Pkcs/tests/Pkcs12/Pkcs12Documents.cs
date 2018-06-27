// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Test.Cryptography;

namespace System.Security.Cryptography.Pkcs.Tests.Pkcs12
{
    internal static class Pkcs12Documents
    {
        internal static readonly ReadOnlyMemory<byte> EmptyPfx = (
            "304F020103301106092A864886F70D010701A004040230003037301F30070605" +
            "2B0E03021A0414822078BC83E955E314BDA908D76D4C5177CC94EB0414711018" +
            "F2897A44A90E92779CB655EA11814EC598").HexToByteArray();
    }
}
