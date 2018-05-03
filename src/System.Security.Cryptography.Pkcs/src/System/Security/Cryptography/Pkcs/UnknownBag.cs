// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography.Pkcs
{
    internal sealed class UnknownBag : Pkcs12SafeBag
    {
        private readonly ReadOnlyMemory<byte> _bagValue;

        internal UnknownBag(string oidValue, ReadOnlyMemory<byte> bagValue)
            : base(oidValue)
        {
            _bagValue = bagValue;
        }

        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
        {
            if (destination.Length < _bagValue.Length)
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = destination.Length;
            _bagValue.Span.CopyTo(destination);
            return true;
        }
    }
}
