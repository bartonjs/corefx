// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs.Asn1;
using System.Security.Cryptography.X509Certificates;
using Internal.Cryptography;

namespace System.Security.Cryptography.Pkcs
{
    public sealed class Pkcs12Info
    {
        public ReadOnlyCollection<Pkcs12SafeContents> AuthenticatedSafe { get; private set; }
        public IntegrityMode DataIntegrityMode { get; private set; }

        private Pkcs12Info()
        {
        }

        public bool VerifyMac(ReadOnlySpan<byte> password) => throw null;

        public bool VerifySignature(X509Certificate2 signerCertificate) => throw null;

        public static Pkcs12Info Decode(
            ReadOnlyMemory<byte> encodedBytes,
            out int bytesConsumed)
        {
            AsnReader reader = new AsnReader(encodedBytes, AsnEncodingRules.BER);
            // Trim it to the first value
            encodedBytes = reader.PeekEncodedValue();

            // Copy the data
            byte[] copy = encodedBytes.ToArray();

            Pfx pfx = AsnSerializer.Deserialize<Pfx>(copy, AsnEncodingRules.BER);

            // https://tools.ietf.org/html/rfc7292#section-4 only defines version 3.
            if (pfx.Version != 3)
            {
                throw new CryptographicException("Only version 3 PFX data is supported");
            }

            ReadOnlyMemory<byte> authSafeBytes = ReadOnlyMemory<byte>.Empty;
            IntegrityMode mode = IntegrityMode.Unknown;

            if (pfx.AuthSafe.ContentType == Oids.Pkcs7Data)
            {
                authSafeBytes = Helpers.DecodeOctetString(pfx.AuthSafe.Content);
                
                if (pfx.MacData.HasValue)
                {
                    mode = IntegrityMode.Password;
                }
            }
            else if (pfx.AuthSafe.ContentType == Oids.Pkcs7Signed)
            {
                SignedDataAsn signedData =
                    AsnSerializer.Deserialize<SignedDataAsn>(pfx.AuthSafe.Content, AsnEncodingRules.BER);

                mode = IntegrityMode.PublicKey;

                if (signedData.EncapContentInfo.ContentType == Oids.Pkcs7Data)
                {
                    authSafeBytes = signedData.EncapContentInfo.Content.GetValueOrDefault();
                }

                if (pfx.MacData.HasValue)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }
            }

            if (mode == IntegrityMode.Unknown)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            ContentInfoAsn[] authSafeData =
                AsnSerializer.Deserialize<ContentInfoAsn[]>(authSafeBytes, AsnEncodingRules.BER);

            ReadOnlyCollection<Pkcs12SafeContents> authSafe;

            if (authSafeData.Length == 0)
            {
                authSafe = new ReadOnlyCollection<Pkcs12SafeContents>(Array.Empty<Pkcs12SafeContents>());
            }
            else
            {
                Pkcs12SafeContents[] contentsArray = new Pkcs12SafeContents[authSafeData.Length];

                for (int i = 0; i < contentsArray.Length; i++)
                {
                    contentsArray[i] = new Pkcs12SafeContents(authSafeData[i]);
                }

                authSafe = new ReadOnlyCollection<Pkcs12SafeContents>(contentsArray);
            }

            bytesConsumed = encodedBytes.Length;

            return new Pkcs12Info
            {
                AuthenticatedSafe = authSafe,
                DataIntegrityMode = mode,
            };
        }

        public enum IntegrityMode
        {
            Unknown,
            Password,
            PublicKey,
        }
    }
}
