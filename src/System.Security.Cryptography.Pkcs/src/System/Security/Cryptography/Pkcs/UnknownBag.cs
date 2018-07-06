// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography.Pkcs
{
    internal sealed class UnknownBag : Pkcs12SafeBag
    {
        internal UnknownBag(string oidValue, ReadOnlyMemory<byte> bagValue)
            : base(oidValue, bagValue)
        {
        }
    }
}
