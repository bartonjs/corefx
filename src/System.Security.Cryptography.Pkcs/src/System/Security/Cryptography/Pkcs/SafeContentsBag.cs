// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Internal.Cryptography;

namespace System.Security.Cryptography.Pkcs
{
    public sealed class SafeContentsBag : Pkcs12SafeBag
    {
        private SafeContentsBag()
            : base(Oids.Pkcs12SafeContentsBag)
        {
        }

        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten) => throw null;
    }
}
