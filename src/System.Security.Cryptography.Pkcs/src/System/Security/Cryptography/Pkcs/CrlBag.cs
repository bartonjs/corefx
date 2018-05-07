// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography.Pkcs
{
    public sealed class CrlBag : Pkcs12SafeBag
    {
        private CrlBag()
            : base(Oids.Pkcs12CrlBag)
        {
        }

        public ReadOnlyMemory<byte> RawData { get; }

        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten) => throw null;
    }
}
