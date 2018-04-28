// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography.X509Certificates;

namespace System.Security.Cryptography.Pkcs
{
    public sealed partial class KeyBag : Pkcs12SafeBag
    {
        public ReadOnlyMemory<byte> Pkcs8PrivateKey { get; }
        private KeyBag() { }
        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten) => throw null;
    }
}
