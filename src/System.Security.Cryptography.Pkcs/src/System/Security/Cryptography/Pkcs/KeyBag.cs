// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Internal.Cryptography;

namespace System.Security.Cryptography.Pkcs
{
    public sealed class KeyBag : Pkcs12SafeBag
    {
        public ReadOnlyMemory<byte> Pkcs8PrivateKey { get; }

        internal KeyBag(ReadOnlyMemory<byte> pkcs8PrivateKey)
            : base(Oids.Pkcs12KeyBag)
        {
            Pkcs8PrivateKey = pkcs8PrivateKey;
        }

        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
        {
            if (destination.Length < Pkcs8PrivateKey.Length)
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = destination.Length;
            Pkcs8PrivateKey.Span.CopyTo(destination);
            return true;
        }
    }
}
