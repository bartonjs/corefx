// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography.Pkcs
{
    public sealed class SecretBag : Pkcs12SafeBag
    {
        public ReadOnlyMemory<byte> SecretValue { get; }

        private SecretBag()
            : base(Oids.Pkcs12SecretBag)
        {
        }

        public Oid GetSecretType() => throw null;

        protected override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
        {
            throw null;
        }
    }
}
