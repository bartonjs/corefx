// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography.Pkcs
{
    public sealed class ShroudedKeyBag : Pkcs12SafeBag
    {
        public ReadOnlyMemory<byte> EncryptedPkcs8PrivateKey { get; }

        public ShroudedKeyBag(ReadOnlyMemory<byte> encryptedPkcs8PrivateKey, bool skipCopy=false)
            : base(Oids.Pkcs12ShroudedKeyBag)
        {
            EncryptedPkcs8PrivateKey = skipCopy ? encryptedPkcs8PrivateKey : encryptedPkcs8PrivateKey.ToArray();
        }

        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
        {
            if (destination.Length < EncryptedPkcs8PrivateKey.Length)
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = EncryptedPkcs8PrivateKey.Length;
            EncryptedPkcs8PrivateKey.Span.CopyTo(destination);
            return true;
        }
    }
}
