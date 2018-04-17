// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Represents the public and private key of the specified elliptic curve.
    /// </summary>
    public struct ECParameters
    {
        private static readonly string[] s_validOids =
        {
            Oids.EcPublicKey,
            Oids.EcDiffieHellman,
            Oids.EcMQV,
        };

        /// <summary>
        /// Public point.
        /// </summary>
        public ECPoint Q;

        /// <summary>
        /// Private Key. Not always present.
        /// </summary>
        public byte[] D;

        /// <summary>
        /// The Curve.
        /// </summary>
        public ECCurve Curve;

        /// <summary>
        /// Validate the current object.
        /// </summary>
        /// <exception cref="CryptographicException">
        ///     if the key or curve parameters are not valid for the current CurveType.
        /// </exception>
        public void Validate()
        {
            bool hasErrors = false;

            if (Q.X == null ||
                Q.Y == null ||
                Q.X.Length != Q.Y.Length)
            {
                hasErrors = true;
            }
            
            if (!hasErrors)
            {
                if (Curve.IsExplicit)
                {
                    // Explicit curves require D length to match Curve.Order
                    hasErrors = (D != null && (D.Length != Curve.Order.Length));
                }
                else if (Curve.IsNamed)
                {
                    // Named curves require D length to match Q.X and Q.Y
                    hasErrors = (D != null && (D.Length != Q.X.Length));
                }
            }

            if (hasErrors)
            {
                throw new CryptographicException(SR.Cryptography_InvalidCurveKeyParameters);
            }

            Curve.Validate();
        }

        //public static ECParameters FromECPrivateKey(ReadOnlySpan<byte> source, out int bytesRead)
        //{
        //    // RFC 5915.
        //    throw new NotImplementedException();
        //}

        private static void FromECPrivateKey(
            in ECPrivateKey key,
            in AlgorithmIdentifierAsn algId,
            out ECParameters ret)
        {
            ValidateParameters(key.Parameters, algId);

            if (key.Version != 1)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            // Implementation limitation
            if (key.PublicKey == null)
            {
                throw new CryptographicException(SR.Cryptography_NotValidPublicOrPrivateKey);
            }

            ReadOnlySpan<byte> publicKeyBytes = key.PublicKey.Value.Span;

            if (publicKeyBytes.Length == 0)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            if (publicKeyBytes[0] != 0x04)
            {
                throw new CryptographicException("Uncompressed point format required");
            }

            // https://www.secg.org/sec1-v2.pdf, 2.3.4, #3 (M has length 2 * CEIL(log2(q)/8) + 1)
            if (publicKeyBytes.Length != 2 * key.PrivateKey.Length + 1)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            ECDomainParameters domainParameters;

            if (key.Parameters != null)
            {
                domainParameters = key.Parameters.Value;
            }
            else
            {
                domainParameters = AsnSerializer.Deserialize<ECDomainParameters>(
                    algId.Parameters.Value,
                    AsnEncodingRules.DER);
            }

            ret = new ECParameters
            {
                Curve = GetCurve(domainParameters),
                Q =
                {
                    X = publicKeyBytes.Slice(1, key.PrivateKey.Length).ToArray(),
                    Y = publicKeyBytes.Slice(1 + key.PrivateKey.Length).ToArray(),
                },
                D = key.PrivateKey.ToArray(),
            };

            ret.Validate();
        }

        private static void FromECPublicKey(in ReadOnlyMemory<byte> key, in AlgorithmIdentifierAsn algId, out ECParameters ret)
        {
            if (algId.Parameters == null)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            ReadOnlySpan<byte> publicKeyBytes = key.Span;

            if (publicKeyBytes.Length == 0)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            if (publicKeyBytes[0] != 0x04)
            {
                throw new CryptographicException("Uncompressed point format required");
            }

            // https://www.secg.org/sec1-v2.pdf, 2.3.4, #3 (M has length 2 * CEIL(log2(q)/8) + 1)
            if ((publicKeyBytes.Length & 0x01) != 1)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            int fieldWidth = publicKeyBytes.Length / 2;

            ECDomainParameters domainParameters = AsnSerializer.Deserialize<ECDomainParameters>(
                algId.Parameters.Value,
                AsnEncodingRules.DER);

            ret = new ECParameters
            {
                Curve = GetCurve(domainParameters),
                Q =
                {
                    X = publicKeyBytes.Slice(1, fieldWidth).ToArray(),
                    Y = publicKeyBytes.Slice(1 + fieldWidth).ToArray(),
                },
            };

            ret.Validate();
        }

        private static void ValidateParameters(ECDomainParameters? keyParameters, in AlgorithmIdentifierAsn algId)
        {
            // At least one is required
            if (keyParameters == null && algId.Parameters == null)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            // If they are both specified they must match.
            if (keyParameters != null && algId.Parameters != null)
            {
                ReadOnlySpan<byte> algIdParameters = algId.Parameters.Value.Span;
                byte[] verify = ArrayPool<byte>.Shared.Rent(algIdParameters.Length);

                // X.509 SubjectPublicKeyInfo specifies DER encoding.
                // RFC 5915 specifies DER encoding for EC Private Keys.
                // So we can compare as DER.
                using (AsnWriter writer = AsnSerializer.Serialize(keyParameters.Value, AsnEncodingRules.DER))
                {
                    if (!writer.TryEncode(verify, out int written) ||
                        written != algIdParameters.Length ||
                        !algIdParameters.SequenceEqual(verify.AsSpan(0, written)))
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }
                }
            }
        }

        private static ECCurve GetCurve(in ECDomainParameters domainParameters)
        {
            if (domainParameters.Named == null)
            {
                throw new NotImplementedException("Only wrote named");
            }

            Oid curveOid = domainParameters.Named;

            switch (curveOid.Value)
            {
                case Oids.secp256r1:
                    curveOid = new Oid(Oids.secp256r1, "nistP256");
                    break;
                case Oids.secp384r1:
                    curveOid = new Oid(Oids.secp384r1, "nistP384");
                    break;
                case Oids.secp521r1:
                    curveOid = new Oid(Oids.secp521r1, "nistP521");
                    break;
            }

            return ECCurve.CreateFromOid(curveOid);
        }

        public static ECParameters FromPkcs8PrivateKey(ReadOnlySpan<byte> source, out int bytesRead)
        {
            KeyFormatHelper.ReadPkcs8<ECParameters, ECPrivateKey>(
                s_validOids,
                source,
                FromECPrivateKey,
                out bytesRead,
                out ECParameters ret);

            return ret;
        }

        public static ECParameters FromEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> source, out int bytesRead) => throw null;
        public static ECParameters FromEncryptedPkcs8PrivateKey(ReadOnlySpan<byte> passwordBytes, ReadOnlySpan<byte> source, out int bytesRead) => throw null;

        public static ECParameters FromSubjectPublicKeyInfo(ReadOnlySpan<byte> source, out int bytesRead)
        {
            KeyFormatHelper.ReadSubjectPublicKeyInfo<ECParameters, ReadOnlyMemory<byte>>(
                s_validOids,
                source,
                FromECPublicKey,
                out bytesRead,
                out ECParameters ret);

            return ret;
        }

        public byte[] ToPkcs8PrivateKey()
        {
            if (!TryWritePkcs8PrivateKey(true, Span<byte>.Empty, out _, out byte[] ret))
            {
                Debug.Fail("TryWritePkcs8PrivateKey failed in allocation mode");
                throw new CryptographicException();
            }

            return ret;
        }

        public byte[] ToSubjectPublicKeyInfo()
        {
            if (!TryWriteSubjectPublicKeyInfo(true, Span<byte>.Empty, out _, out byte[] ret))
            {
                Debug.Fail("TryWriteSubjectPublicKeyInfo failed in allocation mode");
                throw new CryptographicException();
            }

            return ret;
        }

        public byte[] ToEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, HashAlgorithmName pbkdf2HashAlgorithm, int pbkdf2IterationCount, Pkcs8.EncryptionAlgorithm encryptionAlgorithm) => throw null;
        public byte[] ToEncryptedPkcs8PrivateKey(ReadOnlySpan<byte> passwordBytes, HashAlgorithmName pbkdf2HashAlgorithm, int pbkdf2IterationCount, Pkcs8.EncryptionAlgorithm encryptionAlgorithm) => throw null;

        public bool TryWritePkcs8PrivateKey(Span<byte> destination, out int bytesWritten) =>
            TryWritePkcs8PrivateKey(false, destination, out bytesWritten, out _);

        public bool TryWriteEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, HashAlgorithmName pbkdf2HashAlgorithm, int pbkdf2IterationCount, Pkcs8.EncryptionAlgorithm encryptionAlgorithm, Span<byte> destination, out int bytesWritten) => throw null;
        public bool TryWriteEncryptedPkcs8PrivateKey(ReadOnlySpan<byte> passwordBytes, HashAlgorithmName pbkdf2HashAlgorithm, int pbkdf2IterationCount, Pkcs8.EncryptionAlgorithm encryptionAlgorithm, Span<byte> destination, out int bytesWritten) => throw null;

        public bool TryWriteSubjectPublicKeyInfo(Span<byte> destination, out int bytesWritten) =>
            TryWriteSubjectPublicKeyInfo(false, destination, out bytesWritten, out _);

        private bool TryWriteSubjectPublicKeyInfo(
            bool createArray,
            Span<byte> destination,
            out int bytesWritten,
            out byte[] createdArray)
        {
            Validate();

            using (AsnWriter writer = new AsnWriter(AsnEncodingRules.DER))
            {
                // SubjectPublicKeyInfo
                writer.PushSequence();

                // algorithm
                {
                    writer.PushSequence();

                    writer.WriteObjectIdentifier(Oids.EcPublicKey);
                    WriteEcParameters(writer);

                    writer.PopSequence();
                }

                // subjectPublicKey
                WriteUncompressedPublicKey(writer);

                writer.PopSequence();

                if (createArray)
                {
                    createdArray = writer.Encode();
                    bytesWritten = createdArray.Length;
                    return true;
                }

                createdArray = null;
                return writer.TryEncode(destination, out bytesWritten);
            }
        }

        private bool TryWritePkcs8PrivateKey(
            bool createArray,
            Span<byte> destination,
            out int bytesWritten,
            out byte[] createdArray)
        {
            Validate();

            if (D == null)
            {
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
            }

            using (AsnWriter writer = new AsnWriter(AsnEncodingRules.DER))
            using (AsnWriter ecPrivateKey = WriteEcPrivateKey())
            {
                // PrivateKeyInfo
                writer.PushSequence();

                // version 0 format
                writer.WriteInteger(0);

                // privateKeyAlgorithm
                {
                    writer.PushSequence();
                    writer.WriteObjectIdentifier(Oids.EcPublicKey);
                    WriteEcParameters(writer);
                    writer.PopSequence();
                }

                writer.WriteOctetString(ecPrivateKey.EncodeAsSpan());

                writer.PopSequence();

                if (createArray)
                {
                    createdArray = writer.Encode();
                    bytesWritten = createdArray.Length;
                    return true;
                }

                createdArray = null;
                return writer.TryEncode(destination, out bytesWritten);
            }
        }

        private void WriteEcParameters(AsnWriter writer)
        {
            if (Curve.IsNamed)
            {
                Oid oid = Curve.Oid;

                if (string.IsNullOrEmpty(oid.Value))
                {
                    oid = Oid.FromFriendlyName(oid.FriendlyName, OidGroup.All);
                }

                writer.WriteObjectIdentifier(oid.Value);
            }
            else
            {
                throw new CryptographicException(SR.Cryptography_ECC_NamedCurvesOnly);
            }
        }

        private void WriteUncompressedPublicKey(AsnWriter writer)
        {
            int publicKeyLength = Q.X.Length * 2 + 1;
            Span<byte> publicKeyBytes = stackalloc byte[0];
            byte[] publicKeyRented = null;

            if (publicKeyLength < 256)
            {
                publicKeyBytes = stackalloc byte[publicKeyLength];
            }
            else
            {
                publicKeyRented = ArrayPool<byte>.Shared.Rent(publicKeyLength);
                publicKeyBytes = publicKeyRented.AsSpan(0, publicKeyLength);
            }

            try
            {
                publicKeyBytes[0] = 0x04;
                Q.X.AsSpan().CopyTo(publicKeyBytes.Slice(1));
                Q.Y.AsSpan().CopyTo(publicKeyBytes.Slice(1 + Q.X.Length));

                writer.WriteBitString(publicKeyBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicKeyBytes);

                if (publicKeyRented != null)
                {
                    ArrayPool<byte>.Shared.Return(publicKeyRented);
                }
            }
        }

        private AsnWriter WriteEcPrivateKey()
        {
            bool returning = false;
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

            try
            {
                // ECPrivateKey
                writer.PushSequence();

                // version 1
                writer.WriteInteger(1);
                
                // privateKey
                writer.WriteOctetString(D);

                // domainParameters
                {
                    Asn1Tag explicit0 = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
                    writer.PushSequence(explicit0);

                    WriteEcParameters(writer);

                    writer.PopSequence(explicit0);
                }

                // publicKey
                {
                    Asn1Tag explicit1 = new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true);
                    writer.PushSequence(explicit1);

                    WriteUncompressedPublicKey(writer);

                    writer.PopSequence(explicit1);
                }

                writer.PopSequence();
                returning = true;
                return writer;
            }
            finally
            {
                if (!returning)
                {
                    writer.Dispose();
                }
            }
        }
    }

    // https://www.secg.org/sec1-v2.pdf, C.4
    //
    // ECPrivateKey ::= SEQUENCE {
    //   version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    //   privateKey OCTET STRING,
    //   parameters [0] ECDomainParameters {{ SECGCurveNames }} OPTIONAL,
    //   publicKey [1] BIT STRING OPTIONAL
    // }
    [StructLayout(LayoutKind.Sequential)]
    internal struct ECPrivateKey
    {
        public byte Version;

        [OctetString]
        public ReadOnlyMemory<byte> PrivateKey;

        [OptionalValue]
        [ExpectedTag(0, ExplicitTag = true)]
        public ECDomainParameters? Parameters;

        [BitString, OptionalValue]
        [ExpectedTag(1, ExplicitTag = true)]
        public ReadOnlyMemory<byte>? PublicKey;
    }

    // https://www.secg.org/sec1-v2.pdf, C.2
    //
    // ECDomainParameters{ECDOMAIN:IOSet} ::= CHOICE {
    //   specified SpecifiedECDomain,
    //   named ECDOMAIN.&id({IOSet}),
    //   implicitCA NULL
    // }
    [Choice]
    [StructLayout(LayoutKind.Sequential)]
    internal struct ECDomainParameters
    {
        public SpecifiedECDomain? Specified;

        [ObjectIdentifier(PopulateFriendlyName = true)]
        public Oid Named;
    }

    // https://www.secg.org/sec1-v2.pdf, C.2
    //
    // SpecifiedECDomain ::= SEQUENCE {
    //   version SpecifiedECDomainVersion(ecdpVer1 | ecdpVer2 | ecdpVer3, ...),
    //   fieldID FieldID {{FieldTypes}},
    //   curve Curve,
    //   base ECPoint,
    //   order INTEGER,
    //   cofactor INTEGER OPTIONAL,
    //   hash HashAlgorithm OPTIONAL,
    //   ...
    // }
    //
    // HashAlgorithm ::= AlgorithmIdentifier {{ HashFunctions }}
    // ECPoint ::= OCTET STRING
    [StructLayout(LayoutKind.Sequential)]
    internal struct SpecifiedECDomain
    {
        public byte Version;

        public FieldID FieldID;

        public Curve Curve;

        [OctetString]
        public ReadOnlyMemory<byte> Base;

        [Integer]
        public ReadOnlyMemory<byte> Order;

        [Integer, OptionalValue]
        public ReadOnlyMemory<byte>? Cofactor;

        [OptionalValue]
        [ObjectIdentifier(PopulateFriendlyName = true)]
        public Oid Hash;
    }

    // https://www.secg.org/sec1-v2.pdf, C.1
    //
    // FieldID { FIELD-ID:IOSet } ::= SEQUENCE { -- Finite field
    //   fieldType FIELD-ID.&id({IOSet}),
    //   parameters FIELD-ID.&Type({IOSet}{@fieldType})
    // }
    [StructLayout(LayoutKind.Sequential)]
    internal struct FieldID
    {
        [ObjectIdentifier]
        public string FieldType;

        [AnyValue]
        public ReadOnlyMemory<byte> Parameters;
    }

    // https://www.secg.org/sec1-v2.pdf, C.2
    //
    // Curve ::= SEQUENCE {
    //   a FieldElement,
    //   b FieldElement,
    //   seed BIT STRING OPTIONAL
    //   -- Shall be present if used in SpecifiedECDomain
    //   -- with version equal to ecdpVer2 or ecdpVer3
    // }
    //
    // FieldElement ::= OCTET STRING
    [StructLayout(LayoutKind.Sequential)]
    internal struct Curve
    {
        [OctetString]
        public ReadOnlyMemory<byte> A;

        [OctetString]
        public ReadOnlyMemory<byte> B;

        [BitString, OptionalValue]
        public ReadOnlyMemory<byte>? Seed;
    }
}
