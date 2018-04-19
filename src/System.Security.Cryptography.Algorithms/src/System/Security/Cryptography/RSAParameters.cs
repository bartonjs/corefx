// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography
{
    [StructLayout(LayoutKind.Sequential)]
    public struct RSAParameters
    {
        private static readonly string[] s_validOids =
        {
            Oids.RsaEncryption,
            // RSA-PSS, also?
        };

        public byte[] D;
        public byte[] DP;
        public byte[] DQ;
        public byte[] Exponent;
        public byte[] InverseQ;
        public byte[] Modulus;
        public byte[] P;
        public byte[] Q;

        public static RSAParameters FromSubjectPublicKeyInfo(ReadOnlySpan<byte> source, out int bytesRead)
        {
            KeyFormatHelper.ReadSubjectPublicKeyInfo<RSAParameters, RSAPublicKey>(
                s_validOids,
                source,
                FromPkcs1PublicKey,
                out bytesRead,
                out RSAParameters ret);

            return ret;
        }

        public static RSAParameters FromPkcs1PublicKey(ReadOnlySpan<byte> source, out int bytesRead)
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(source.Length);
            source.CopyTo(buf);
            Memory<byte> rwTmp = buf.AsMemory(0, source.Length);
            ReadOnlyMemory<byte> tmp = rwTmp;

            try
            {
                RSAPublicKey publicKey =
                    AsnSerializer.Deserialize<RSAPublicKey>(tmp, AsnEncodingRules.BER, out int read);

                AlgorithmIdentifierAsn ignored = default;
                FromPkcs1PublicKey(publicKey, ignored, out RSAParameters ret);

                bytesRead = read;
                return ret;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(rwTmp.Span);
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        private static void FromPkcs1PublicKey(
            in RSAPublicKey key,
            in AlgorithmIdentifierAsn algId,
            out RSAParameters ret)
        {
            if (!algId.HasNullEquivalentParameters())
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            ret = new RSAParameters()
            {
                Modulus = key.Modulus.ToByteArray(isUnsigned: true, isBigEndian: true),
                Exponent = key.PublicExponent.ToByteArray(isUnsigned: true, isBigEndian: true),
            };
        }

        public static RSAParameters FromPkcs1PrivateKey(ReadOnlySpan<byte> source, out int bytesRead)
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(source.Length);
            source.CopyTo(buf);
            Memory<byte> rwTmp = buf.AsMemory(0, source.Length);
            ReadOnlyMemory<byte> tmp = rwTmp;

            try
            {
                RSAPrivateKey privateKey =
                    AsnSerializer.Deserialize<RSAPrivateKey>(tmp, AsnEncodingRules.BER, out int read);

                AlgorithmIdentifierAsn ignored = default;
                FromPkcs1PrivateKey(privateKey, ignored, out RSAParameters ret);
                bytesRead = read;
                return ret;
            }
            finally
            {
                buf.AsSpan(0, source.Length).Clear();
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        private static void FromPkcs1PrivateKey(
            in RSAPrivateKey key,
            in AlgorithmIdentifierAsn algId,
            out RSAParameters ret)
        {
            if (!algId.HasNullEquivalentParameters())
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            if (key.Version != 0)
            {
                throw new CryptographicException(
                    SR.Format(SR.Cryptography_RSAPrivateKey_V0Only, key.Version));
            }

            // The modulus size determines the encoded output size of the CRT parameters.
            byte[] n = key.Modulus.ToByteArray(isUnsigned: true, isBigEndian: true);
            int halfModulusLength = (n.Length + 1) / 2;

            ret = new RSAParameters
            {
                Modulus = n,
                Exponent = key.PublicExponent.ToByteArray(isUnsigned: true, isBigEndian: true),
                D = ExportMinimumSize(key.PrivateExponent, n.Length),
                P = ExportMinimumSize(key.Prime1, halfModulusLength),
                Q = ExportMinimumSize(key.Prime2, halfModulusLength),
                DP = ExportMinimumSize(key.Exponent1, halfModulusLength),
                DQ = ExportMinimumSize(key.Exponent2, halfModulusLength),
                InverseQ = ExportMinimumSize(key.Coefficient, halfModulusLength),
            };
        }

        public static RSAParameters FromPkcs8PrivateKey(ReadOnlySpan<byte> source, out int bytesRead)
        {
            KeyFormatHelper.ReadPkcs8<RSAParameters, RSAPrivateKey>(
                s_validOids,
                source,
                FromPkcs1PrivateKey,
                out bytesRead,
                out RSAParameters ret);

            return ret;
        }

        public static RSAParameters FromEncryptedPkcs8PrivateKey(
            ReadOnlySpan<char> password,
            ReadOnlySpan<byte> source,
            out int bytesRead)
        {
            KeyFormatHelper.ReadEncryptedPkcs8<RSAParameters, RSAPrivateKey>(
                s_validOids,
                source,
                password,
                FromPkcs1PrivateKey,
                out bytesRead,
                out RSAParameters ret);

            return ret;
        }

        public static RSAParameters FromEncryptedPkcs8PrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            ReadOnlySpan<byte> source,
            out int bytesRead)
        {
            KeyFormatHelper.ReadEncryptedPkcs8<RSAParameters, RSAPrivateKey>(
                s_validOids,
                source,
                passwordBytes,
                FromPkcs1PrivateKey,
                out bytesRead,
                out RSAParameters ret);

            return ret;
        }

        private static byte[] ExportMinimumSize(BigInteger value, int minimumLength)
        {
            byte[] target = new byte[minimumLength];

            if (value.TryWriteBytes(target, out int bytesWritten, isUnsigned: true, isBigEndian: true))
            {
                if (bytesWritten < minimumLength)
                {
                    Buffer.BlockCopy(target, 0, target, minimumLength - bytesWritten, bytesWritten);
                    target.AsSpan(0, minimumLength - bytesWritten).Clear();
                }

                return target;
            }

            // TODO: Should we be Minimum and grow here (new functionality), or Fixed and throw (current limitations)?
            // Really the question is do we care about P.Length != Q.Length as a viable scenario.
            return value.ToByteArray(isUnsigned: true, isBigEndian: true);
        }

        public byte[] ToPkcs1PublicKey()
        {
            using (AsnWriter writer = WritePkcs1PublicKey())
            {
                return writer.Encode();
            }
        }

        public byte[] ToSubjectPublicKeyInfo()
        {
            using (AsnWriter writer = WriteSubjectPublicKeyInfo())
            {
                return writer.Encode();
            }
        }

        public byte[] ToPkcs1PrivateKey()
        {
            using (AsnWriter writer = WritePkcs1PrivateKey())
            {
                return writer.Encode();
            }
        }

        public byte[] ToPkcs8PrivateKey()
        {
            using (AsnWriter writer = WritePkcs8PrivateKey())
            {
                return writer.Encode();
            }
        }

        public byte[] ToEncryptedPkcs8PrivateKey(
            ReadOnlySpan<char> password,
            HashAlgorithmName pbkdf2HashAlgorithm,
            int pbkdf2IterationCount,
            Pkcs8.EncryptionAlgorithm encryptionAlgorithm)
        {
            using (AsnWriter pkcs8PrivateKey = WritePkcs8PrivateKey())
            using (AsnWriter writer = KeyFormatHelper.WriteEncryptedPkcs8(
                password,
                pkcs8PrivateKey,
                encryptionAlgorithm,
                pbkdf2HashAlgorithm,
                pbkdf2IterationCount))
            {
                return writer.Encode();
            }
        }

        public byte[] ToEncryptedPkcs8PrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            HashAlgorithmName pbkdf2HashAlgorithm,
            int pbkdf2IterationCount,
            Pkcs8.EncryptionAlgorithm encryptionAlgorithm)
        {
            using (AsnWriter pkcs8PrivateKey = WritePkcs8PrivateKey())
            using (AsnWriter writer = KeyFormatHelper.WriteEncryptedPkcs8(
                passwordBytes,
                pkcs8PrivateKey,
                encryptionAlgorithm,
                pbkdf2HashAlgorithm,
                pbkdf2IterationCount))
            {
                return writer.Encode();
            }
        }

        public bool TryWritePkcs1PublicKey(Span<byte> destination, out int bytesWritten)
        {
            using (AsnWriter writer = WritePkcs1PublicKey())
            {
                return writer.TryEncode(destination, out bytesWritten);
            }
        }

        public bool TryWriteSubjectPublicKeyInfo(Span<byte> destination, out int bytesWritten)
        {
            using (AsnWriter writer = WriteSubjectPublicKeyInfo())
            {
                return writer.TryEncode(destination, out bytesWritten);
            }
        }

        public bool TryWritePkcs1PrivateKey(Span<byte> destination, out int bytesWritten)
        {
            using (AsnWriter writer = WritePkcs1PrivateKey())
            {
                return writer.TryEncode(destination, out bytesWritten);
            }
        }

        public bool TryWritePkcs8PrivateKey(Span<byte> destination, out int bytesWritten)
        {
            using (AsnWriter writer = WritePkcs8PrivateKey())
            {
                return writer.TryEncode(destination, out bytesWritten);
            }
        }

        public bool TryWriteEncryptedPkcs8PrivateKey(
            ReadOnlySpan<char> password,
            HashAlgorithmName pbkdf2HashAlgorithm,
            int pbkdf2IterationCount,
            Pkcs8.EncryptionAlgorithm encryptionAlgorithm,
            Span<byte> destination,
            out int bytesWritten)
        {
            using (AsnWriter pkcs8PrivateKey = WritePkcs8PrivateKey())
            using (AsnWriter writer = KeyFormatHelper.WriteEncryptedPkcs8(
                password,
                pkcs8PrivateKey,
                encryptionAlgorithm,
                pbkdf2HashAlgorithm,
                pbkdf2IterationCount))
            {
                return writer.TryEncode(destination, out bytesWritten);
            }
        }

        public bool TryWriteEncryptedPkcs8PrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            HashAlgorithmName pbkdf2HashAlgorithm,
            int pbkdf2IterationCount,
            Pkcs8.EncryptionAlgorithm encryptionAlgorithm,
            Span<byte> destination,
            out int bytesWritten)
        {
            using (AsnWriter pkcs8PrivateKey = WritePkcs8PrivateKey())
            using (AsnWriter writer = KeyFormatHelper.WriteEncryptedPkcs8(
                passwordBytes,
                pkcs8PrivateKey,
                encryptionAlgorithm,
                pbkdf2HashAlgorithm,
                pbkdf2IterationCount))
            {
                return writer.TryEncode(destination, out bytesWritten);
            }
        }

        private AsnWriter WriteSubjectPublicKeyInfo()
        {
            if (Modulus == null || Exponent == null)
            {
                throw new InvalidOperationException(SR.Cryptography_InvalidRsaParameters);
            }

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            bool returning = false;

            try
            {
                using (AsnWriter pkcs1Writer = WritePkcs1PublicKey())
                {
                    // SubjectPublicKeyInfo
                    writer.PushSequence();

                    // SPKI.Algorithm (AlgorithmIdentifier)
                    {
                        writer.PushSequence();
                        writer.WriteObjectIdentifier(Oids.RsaEncryption);

                        // https://tools.ietf.org/html/rfc3447#appendix-C
                        //
                        // --
                        // -- When rsaEncryption is used in an AlgorithmIdentifier the
                        // -- parameters MUST be present and MUST be NULL.
                        // --
                        writer.WriteNull();

                        writer.PopSequence();
                    }

                    // SPKI.subjectPublicKey
                    writer.WriteBitString(pkcs1Writer.EncodeAsSpan());

                    writer.PopSequence();
                }

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

        private AsnWriter WritePkcs1PublicKey()
        {
            if (Modulus == null || Exponent == null)
            {
                throw new InvalidOperationException(SR.Cryptography_InvalidRsaParameters);
            }

            BigInteger n = new BigInteger(Modulus, isUnsigned: true, isBigEndian: true);
            BigInteger e = new BigInteger(Exponent, isUnsigned: true, isBigEndian: true);

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();
            writer.WriteInteger(n);
            writer.WriteInteger(e);
            writer.PopSequence();

            return writer;
        }

        private AsnWriter WritePkcs1PrivateKey()
        {
            if (Modulus == null || Exponent == null)
            {
                throw new InvalidOperationException(SR.Cryptography_InvalidRsaParameters);
            }

            if (D == null ||
                P == null ||
                Q == null ||
                DP == null ||
                DQ == null ||
                InverseQ == null)
            {
                throw new InvalidOperationException(SR.Cryptography_NotValidPrivateKey);
            }

            BigInteger n = new BigInteger(Modulus, isUnsigned: true, isBigEndian: true);
            BigInteger e = new BigInteger(Exponent, isUnsigned: true, isBigEndian: true);
            BigInteger d = new BigInteger(D, isUnsigned: true, isBigEndian: true);
            BigInteger p = new BigInteger(P, isUnsigned: true, isBigEndian: true);
            BigInteger q = new BigInteger(Q, isUnsigned: true, isBigEndian: true);
            BigInteger dp = new BigInteger(DP, isUnsigned: true, isBigEndian: true);
            BigInteger dq = new BigInteger(DQ, isUnsigned: true, isBigEndian: true);
            BigInteger qInv = new BigInteger(InverseQ, isUnsigned: true, isBigEndian: true);

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

            writer.PushSequence();

            // Format version 0
            writer.WriteInteger(0);
            writer.WriteInteger(n);
            writer.WriteInteger(e);
            writer.WriteInteger(d);
            writer.WriteInteger(p);
            writer.WriteInteger(q);
            writer.WriteInteger(dp);
            writer.WriteInteger(dq);
            writer.WriteInteger(qInv);

            writer.PopSequence();

            return writer;
        }

        private AsnWriter WritePkcs8PrivateKey()
        {
            using (AsnWriter pkcs1Writer = WritePkcs1PrivateKey())
            {
                ReadOnlySpan<byte> pkcs1PrivateKey = pkcs1Writer.EncodeAsSpan();

                // https://tools.ietf.org/html/rfc5208#section-5
                //
                // PrivateKeyInfo ::= SEQUENCE {
                //   version                   Version,
                //   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
                //   privateKey                PrivateKey,
                //   attributes           [0]  IMPLICIT Attributes OPTIONAL }
                // 
                // Version ::= INTEGER
                // PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
                // PrivateKey ::= OCTET STRING
                AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

                // PrivateKeyInfo
                writer.PushSequence();

                // https://tools.ietf.org/html/rfc5208#section-5 says the current version is 0.
                writer.WriteInteger(0);

                // PKI.Algorithm (AlgorithmIdentifier)
                {
                    writer.PushSequence();
                    writer.WriteObjectIdentifier(Oids.RsaEncryption);

                    // https://tools.ietf.org/html/rfc3447#appendix-C
                    //
                    // --
                    // -- When rsaEncryption is used in an AlgorithmIdentifier the
                    // -- parameters MUST be present and MUST be NULL.
                    // --
                    writer.WriteNull();

                    writer.PopSequence();
                }

                // PKI.privateKey
                writer.WriteOctetString(pkcs1PrivateKey);

                // We don't currently accept attributes, so... done.
                writer.PopSequence();
                return writer;
            }
        }
    }

    // https://tools.ietf.org/html/rfc5208#section-6
    //
    // EncryptedPrivateKeyInfo ::= SEQUENCE {
    //  encryptionAlgorithm  EncryptionAlgorithmIdentifier,
    //  encryptedData        EncryptedData }
    //
    // EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
    // EncryptedData ::= OCTET STRING
    [StructLayout(LayoutKind.Sequential)]
    internal struct EncryptedPrivateKeyInfo
    {
        public AlgorithmIdentifierAsn EncryptionAlgorithm;

        [OctetString]
        public ReadOnlyMemory<byte> EncryptedData;
    }

    // https://tools.ietf.org/html/rfc5208#section-5
    //
    // PrivateKeyInfo ::= SEQUENCE {
    //   version                   Version,
    //   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
    //   privateKey                PrivateKey,
    //   attributes           [0]  IMPLICIT Attributes OPTIONAL }
    // 
    // Version ::= INTEGER
    // PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
    // PrivateKey ::= OCTET STRING
    // Attributes ::= SET OF Attribute
    [StructLayout(LayoutKind.Sequential)]
    internal struct PrivateKeyInfo
    {
        public byte Version;

        public AlgorithmIdentifierAsn PrivateKeyAlgorithm;

        [OctetString]
        public ReadOnlyMemory<byte> PrivateKey;

        [ExpectedTag(0)]
        [OptionalValue]
        public AttributeAsn[] Attributes;
    }

    // https://tools.ietf.org/html/rfc5652#section-5.3
    //
    // Attribute ::= SEQUENCE {
    //   attrType OBJECT IDENTIFIER,
    //   attrValues SET OF AttributeValue }
    //
    // AttributeValue ::= ANY
    [StructLayout(LayoutKind.Sequential)]
    internal struct AttributeAsn
    {
        public Oid AttrType;

        [AnyValue]
        public ReadOnlyMemory<byte> AttrValues;
    }

    // https://tools.ietf.org/html/rfc3280#section-4.1.1.2
    //
    // AlgorithmIdentifier  ::=  SEQUENCE  {
    //   algorithm               OBJECT IDENTIFIER,
    //   parameters              ANY DEFINED BY algorithm OPTIONAL  }
    [StructLayout(LayoutKind.Sequential)]
    internal struct AlgorithmIdentifierAsn
    {
        [ObjectIdentifier]
        internal string Algorithm;

        [AnyValue]
        [OptionalValue]
        internal ReadOnlyMemory<byte>? Parameters;

        internal bool HasNullEquivalentParameters()
        {
            if (Parameters == null)
            {
                return true;
            }

            ReadOnlyMemory<byte> parameters = Parameters.Value;

            if (parameters.Length != 2)
            {
                return false;
            }

            ReadOnlySpan<byte> paramBytes = parameters.Span;
            return paramBytes[0] == 0x05 && paramBytes[1] == 0x00;
        }
    }

    // https://tools.ietf.org/html/rfc3280#section-4.1
    //
    // SubjectPublicKeyInfo  ::=  SEQUENCE  {
    //   algorithm            AlgorithmIdentifier,
    //   subjectPublicKey     BIT STRING  }
    [StructLayout(LayoutKind.Sequential)]
    internal struct SubjectPublicKeyInfo
    {
        internal AlgorithmIdentifierAsn Algorithm;

        [BitString]
        internal ReadOnlyMemory<byte> SubjectPublicKey;
    }

    // https://tools.ietf.org/html/rfc3447#appendix-C
    //
    // RSAPublicKey ::= SEQUENCE {
    //   modulus           INTEGER,  -- n
    //   publicExponent    INTEGER   -- e
    // }
    [StructLayout(LayoutKind.Sequential)]
    internal struct RSAPublicKey
    {
        internal BigInteger Modulus;
        internal BigInteger PublicExponent;
    }

    // https://tools.ietf.org/html/rfc3447#appendix-C
    //
    // RSAPrivateKey ::= SEQUENCE {
    //   version           Version,
    //   modulus           INTEGER,  -- n
    //   publicExponent    INTEGER,  -- e
    //   privateExponent   INTEGER,  -- d
    //   prime1            INTEGER,  -- p
    //   prime2            INTEGER,  -- q
    //   exponent1         INTEGER,  -- d mod (p-1)
    //   exponent2         INTEGER,  -- d mod (q-1)
    //   coefficient       INTEGER,  -- (inverse of q) mod p
    //   otherPrimeInfos   OtherPrimeInfos OPTIONAL
    // }
    //
    // Version ::= INTEGER { two-prime(0), multi(1) }
    //   (CONSTRAINED BY {
    //     -- version must be multi if otherPrimeInfos present --
    //   })
    //
    // Since we don't support otherPrimeInfos (Version=1) just don't map it in.
    [StructLayout(LayoutKind.Sequential)]
    internal struct RSAPrivateKey
    {
        internal byte Version;
        internal BigInteger Modulus;
        internal BigInteger PublicExponent;
        internal BigInteger PrivateExponent;
        internal BigInteger Prime1;
        internal BigInteger Prime2;
        internal BigInteger Exponent1;
        internal BigInteger Exponent2;
        internal BigInteger Coefficient;
    }
}
