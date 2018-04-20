// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using Internal.Cryptography;

namespace System.Security.Cryptography.X509Certificates
{
    public enum StoreName
    {
        AddressBook = 1, // other people.
        AuthRoot = 2, // third party trusted roots.
        CertificateAuthority = 3, // intermediate CAs.
        Disallowed = 4, // revoked certificates.
        My = 5, // personal certificates.
        Root = 6, // trusted root CAs.
        TrustedPeople = 7, // trusted people (used in EFS).
        TrustedPublisher = 8, // trusted publishers (used in Authenticode).
    }
}

namespace System.Security.Cryptography.Pkcs.Pkcs12
{
    internal sealed class Pkcs12Info
    {

    }

    internal sealed class SafeContents
    {
        public bool IsEncrypted { get; private set; }
        public bool ShouldBeEncrypted { get; private set; }
    }

    internal abstract class SafeBag
    {
        internal protected string OidValue { get; }

        protected SafeBag(string oidValue)
        {
            if (string.IsNullOrEmpty(oidValue))
            {
                throw new ArgumentNullException(nameof(oidValue));
            }

            OidValue = oidValue;
        }

        public List<AsnEncodedData> Attributes { get; set; }

        public Oid GetBagTypeId() => new Oid(OidValue);

        public abstract byte[] Encode();
        public abstract bool TryEncode(Span<byte> destination, out int bytesWritten);

        public static SafeBag Decode(ReadOnlyMemory<byte> source)
        {
            throw new NotImplementedException();
        }
    }

    // Stay internal, let people make their own derived types to get this.
    internal sealed class UnknownSafeBag : SafeBag
    {
        internal UnknownSafeBag(string oidValue)
            : base(oidValue)
        {
        }

        public override byte[] Encode()
        {
            throw new NotImplementedException();
        }

        public override bool TryEncode(Span<byte> destination, out int bytesWritten)
        {
            throw new NotImplementedException();
        }
    }

    internal sealed class KeyBag : SafeBag
    {
        internal KeyBag()
            : base(Oids.Pkcs12KeyBag)
        {
        }

        public override byte[] Encode()
        {
            throw new NotImplementedException();
        }

        public override bool TryEncode(Span<byte> destination, out int bytesWritten)
        {
            throw new NotImplementedException();
        }
    }

    internal sealed class ShroudedKeyBag : SafeBag
    {
        internal ShroudedKeyBag()
            : base(Oids.Pkcs12ShroudedKeyBag)
        {
        }

        public override byte[] Encode()
        {
            throw new NotImplementedException();
        }

        public override bool TryEncode(Span<byte> destination, out int bytesWritten)
        {
            throw new NotImplementedException();
        }
    }

    internal sealed class CertBag : SafeBag
    {
        internal CertBag()
            : base(Oids.Pkcs12CertBag)
        {
        }

        public override byte[] Encode()
        {
            throw new NotImplementedException();
        }

        public override bool TryEncode(Span<byte> destination, out int bytesWritten)
        {
            throw new NotImplementedException();
        }
    }

    internal sealed class CrlBag : SafeBag
    {
        internal CrlBag()
            : base(Oids.Pkcs12CrlBag)
        {
        }

        public override byte[] Encode()
        {
            throw new NotImplementedException();
        }

        public override bool TryEncode(Span<byte> destination, out int bytesWritten)
        {
            throw new NotImplementedException();
        }
    }

    internal sealed class SecretBag : SafeBag
    {
        internal SecretBag()
            : base(Oids.Pkcs12SecretBag)
        {
        }

        public override byte[] Encode()
        {
            throw new NotImplementedException();
        }

        public override bool TryEncode(Span<byte> destination, out int bytesWritten)
        {
            throw new NotImplementedException();
        }
    }

    internal sealed class SafeContentsBag : SafeBag
    {
        internal SafeContentsBag()
            : base(Oids.Pkcs12SafeContentsBag)
        {
        }

        public override byte[] Encode()
        {
            throw new NotImplementedException();
        }

        public override bool TryEncode(Span<byte> destination, out int bytesWritten)
        {
            throw new NotImplementedException();
        }
    }
}
