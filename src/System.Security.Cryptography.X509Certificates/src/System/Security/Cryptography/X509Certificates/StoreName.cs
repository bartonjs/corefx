// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography.X509Certificates;
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
    internal enum Pkcs12IntegrityMode
    {
        Unknown,
        Password,
        PublicKey,
    }

    internal enum Pkcs12ConfidentialityMode
    {
        Unknown,
        None,
        Password,
        PublicKey,
    }

    internal sealed class Pkcs12Info
    {
        public Pkcs12IntegrityMode IntegrityMode { get; private set; }

        public bool VerifyMac(ReadOnlySpan<char> password)
        {
            if (IntegrityMode != Pkcs12IntegrityMode.Password)
            {
                throw new InvalidOperationException("VerifyMac is only valid for password integrity mode.");
            }

            throw new NotImplementedException();
        }
    }

    internal sealed class Pkcs12Builder
    {
        public bool IsSealed { get; private set; }

        public void AddContentsUnencrypted(SafeContents contents)
        {
            throw new NotImplementedException();
        }

        public void AddContentsEncrypted(
            SafeContents contents,
            ReadOnlySpan<char> password,
            HashAlgorithmName pbkdf2HashAlgorithm,
            int pbkdf2IterationCount,
            Pkcs8.EncryptionAlgorithm encryptionAlgorithm)
        {
            throw new NotImplementedException();
        }

        public void AddContentsEnveloped(
            SafeContents contents,
            X509Certificate2 recipientCertificate)
        {
            throw new NotImplementedException();
        }

        public void
    }

    internal sealed class SafeContents
    {
        private List<SafeBag> _contents;

        public bool IsEncrypted { get; private set; }
        public bool ShouldBeEncrypted { get; private set; }

        public ReadOnlyCollection<SafeBag> EnumerateBags()
        {
            if (IsEncrypted)
            {
                throw new InvalidOperationException(
                    "The contents of a safe may not be enumerated while the safe is encrypted.");
            }

            return _contents.AsReadOnly();
        }
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

        /// <summary>
        /// Encode the <c>bagValue</c> contents for the <c>SafeBag</c> ASN.1 type.
        /// </summary>
        public abstract byte[] EncodeValue();

        /// <summary>
        /// Encode the <c>bagValue</c> contents for the <c>SafeBag</c> ASN.1 type, if it fits.
        /// </summary>
        public abstract bool TryEncodeValue(Span<byte> destination, out int bytesWritten);

        public static SafeBag Decode(
            ReadOnlyMemory<byte> source,
            out int bytesRead,
            bool useExistingMemory=false)
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

        public override byte[] EncodeValue()
        {
            throw new NotImplementedException();
        }

        public override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
        {
            throw new NotImplementedException();
        }
    }

    internal sealed class KeyBag : SafeBag
    {
        public ReadOnlyMemory<byte> Pkcs8Data { get; private set; }

        internal KeyBag()
            : base(Oids.Pkcs12KeyBag)
        {
        }

        public override byte[] EncodeValue()
        {
            return Pkcs8Data.ToArray();
        }

        public override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
        {
            if (destination.Length < Pkcs8Data.Length)
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = Pkcs8Data.Length;
            Pkcs8Data.Span.CopyTo(destination);
            return true;
        }

        public static KeyBag BuildKeyBag(in RSAParameters rsaParameters)
        {
            byte[] pkcs8Data = rsaParameters.ToPkcs8PrivateKey();

            return new KeyBag
            {
                Pkcs8Data = pkcs8Data,
            };
        }

        public static KeyBag BuildKeyBag(in DSAParameters dsaParameters)
        {
            byte[] pkcs8Data = dsaParameters.ToPkcs8PrivateKey();

            return new KeyBag
            {
                Pkcs8Data = pkcs8Data,
            };
        }

        public static KeyBag BuildKeyBag(in ECParameters ecParameters)
        {
            byte[] pkcs8Data = ecParameters.ToPkcs8PrivateKey();

            return new KeyBag
            {
                Pkcs8Data = pkcs8Data,
            };
        }

        public static KeyBag BuildKeyBag(ReadOnlyMemory<byte> pkcs8Data, bool useExistingMemory=false)
        {
            throw new NotImplementedException(
                "Parse the PKCS8, then assign either a minimal clone or the provided value");
        }
    }

    internal sealed class ShroudedKeyBag : SafeBag
    {
        private ReadOnlyMemory<byte> _pkcs8Data;

        internal ShroudedKeyBag()
            : base(Oids.Pkcs12ShroudedKeyBag)
        {
        }

        public override byte[] EncodeValue()
        {
            return _pkcs8Data.ToArray();
        }

        public override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
        {
            if (destination.Length < _pkcs8Data.Length)
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = _pkcs8Data.Length;
            _pkcs8Data.Span.CopyTo(destination);
            return true;
        }
    }

    internal sealed class CertBag : SafeBag
    {
        private ReadOnlyMemory<byte> _encoded;
        private byte[] _certDataArray;
        private CertBagAsn _decoded;

        internal CertBag()
            : base(Oids.Pkcs12CertBag)
        {
        }

        public bool IsX509 => _decoded.CertId == Oids.Pkcs12X509CertBagType;

        public override byte[] EncodeValue()
        {
            //if (_encoded.IsEmpty)
            //{
            //    using (AsnWriter writer = AsnSerializer<CertBagAsn>.Serialize(_decoded, AsnEncodingRules.DER))
            //    {
            //        _encoded = writer.Encode();
            //    }
            //}

            Debug.Assert(!_encoded.IsEmpty);
            return _encoded.ToArray();
        }

        public override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
        {
            //if (_encoded.IsEmpty)
            //{
            //    using (AsnWriter writer = AsnSerializer<CertBagAsn>.Serialize(_decoded, AsnEncodingRules.DER))
            //    {
            //        return writer.TryEncode(destination, out bytesWritten);
            //    }
            //}

            if (_encoded.Length < destination.Length)
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = _encoded.Length;
            _encoded.Span.CopyTo(destination);
            return true;
        }

        public X509Certificate2 GetCertificate()
        {
            if (!IsX509)
            {
                throw new InvalidOperationException("RealWrite: Only X509 CertBags are supported for this.");
            }

            return new X509Certificate2(_certDataArray);
        }

        public static CertBag BuildCertBag(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            byte[] certDataArray = certificate.RawData;

            //using (AsnWriter writer = new AsnWriter(AsnEncodingRules.DER))
            {
                //Asn1Tag explicit0 = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
                //writer.PushSequence(explicit0);
                //writer.WriteOctetString(certDataArray);
                //writer.PopSequence();

                CertBagAsn asn = new CertBagAsn
                {
                    CertId = Oids.Pkcs12X509CertBagType,
                    //CertValue = writer.Encode(),
                };

                return new CertBag
                {
                    _certDataArray = certDataArray,
                    _decoded = asn,
                };
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CertBagAsn
        {
            //[ObjectIdentifier]
            public string CertId;
            
            //[AnyValue]
            //[ExectedTag(0, Explicit=true)]
            public ReadOnlyMemory<byte> CertValue;
        }
    }

    internal sealed class CrlBag : SafeBag
    {
        internal CrlBag()
            : base(Oids.Pkcs12CrlBag)
        {
        }

        public override byte[] EncodeValue()
        {
            throw new NotImplementedException();
        }

        public override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
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

        public override byte[] EncodeValue()
        {
            throw new NotImplementedException();
        }

        public override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
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

        public override byte[] EncodeValue()
        {
            throw new NotImplementedException();
        }

        public override bool TryEncodeValue(Span<byte> destination, out int bytesWritten)
        {
            throw new NotImplementedException();
        }
    }
}
