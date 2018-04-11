// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography
{
    [StructLayout(LayoutKind.Sequential)]
    public struct RSAParameters
    {
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
            byte[] buf = ArrayPool<byte>.Shared.Rent(source.Length);
            source.CopyTo(buf);

            try
            {
                return FromSubjectPublicKeyInfo(buf.AsMemory(0, source.Length), out bytesRead);
            }
            finally
            {
                buf.AsSpan(0, source.Length).Clear();
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        private static RSAParameters FromSubjectPublicKeyInfo(ReadOnlyMemory<byte> source, out int bytesRead)
        {
            SubjectPublicKeyInfo spki =
                AsnSerializer.Deserialize<SubjectPublicKeyInfo>(source, AsnEncodingRules.BER, out int read);

            if (spki.Algorithm.Algorithm != Oids.RsaEncryption)
            {
                // TODO: Better message?
                throw new CryptographicException(SR.Cryptography_NotValidPublicOrPrivateKey);
            }

            // No RFC proscribes laxity with spki.algorithm.parameters being NULL vs omitted
            // for RSA specifically, but many RFCs contain text like
            //
            //    NOTE: There are two possible encodings for the AlgorithmIdentifier
            //    parameters field associated with these object identifiers.  The two
            //    alternatives arise from the loss of the OPTIONAL associated with the
            //    algorithm identifier parameters when the 1988 syntax for
            //    AlgorithmIdentifier was translated into the 1997 syntax.  Later, the
            //    OPTIONAL was recovered via a defect report, but by then many people
            //    thought that algorithm parameters were mandatory.  Because of this
            //    history, some implementations encode parameters as a NULL element
            //    while others omit them entirely. [...]
            //
            // (specific quote from https://www.ietf.org/rfc/rfc5754.txt, section 2)
            //
            // Since it's unambiguous, we can go ahead and be lax on read.
            if (spki.Algorithm.Parameters.HasValue)
            {
                ReadOnlySpan<byte> algParameters = spki.Algorithm.Parameters.Value.Span;

                if (algParameters.Length != 2 ||
                    algParameters[0] != 0x05 ||
                    algParameters[1] != 0x00)
                {
                    // TODO: Better message?
                    throw new CryptographicException(SR.Cryptography_NotValidPublicOrPrivateKey);
                }
            }

            RSAParameters key = FromPkcs1PublicKey(spki.SubjectPublicKey, out _);
            bytesRead = read;
            return key;
        }

        public static RSAParameters FromPkcs1PublicKey(ReadOnlySpan<byte> source, out int bytesRead)
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(source.Length);
            source.CopyTo(buf);

            try
            {
                return FromPkcs1PublicKey(buf.AsMemory(0, source.Length), out bytesRead);
            }
            finally
            {
                buf.AsSpan(0, source.Length).Clear();
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        private static RSAParameters FromPkcs1PublicKey(ReadOnlyMemory<byte> source, out int bytesRead)
        {
            RSAPublicKey publicKey =
                AsnSerializer.Deserialize<RSAPublicKey>(source, AsnEncodingRules.BER, out int read);

            RSAParameters rsaParameters = new RSAParameters()
            {
                Modulus = publicKey.Modulus.ToByteArray(isUnsigned: true, isBigEndian: true),
                Exponent = publicKey.PublicExponent.ToByteArray(isUnsigned: true, isBigEndian: true),
            };

            bytesRead = read;
            return rsaParameters;
        }

        public static RSAParameters FromPkcs1PrivateKey(ReadOnlySpan<byte> source, out int bytesRead)
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(source.Length);
            source.CopyTo(buf);

            try
            {
                RSAPrivateKey privateKey =
                    AsnSerializer.Deserialize<RSAPrivateKey>(buf, AsnEncodingRules.BER, out int read);

                if (privateKey.Version != 0)
                {
                    throw new CryptographicException(
                        SR.Format(SR.Cryptography_RSAPrivateKey_V0Only, privateKey.Version));
                }

                // The modulus size determines the encoded output size of the CRT parameters.
                byte[] n = privateKey.Modulus.ToByteArray(isUnsigned: true, isBigEndian: true);
                int halfModulusLength = (n.Length + 1) / 2;

                RSAParameters rsaParameters = new RSAParameters
                {
                    Modulus = n,
                    Exponent = privateKey.PublicExponent.ToByteArray(isUnsigned: true, isBigEndian: true),
                    D = ExportMinimumSize(privateKey.PrivateExponent, n.Length),
                    P = ExportMinimumSize(privateKey.Prime1, halfModulusLength),
                    Q = ExportMinimumSize(privateKey.Prime2, halfModulusLength),
                    DP = ExportMinimumSize(privateKey.Exponent1, halfModulusLength),
                    DQ = ExportMinimumSize(privateKey.Exponent2, halfModulusLength),
                    InverseQ = ExportMinimumSize(privateKey.Coefficient, halfModulusLength),
                };

                bytesRead = read;
                return rsaParameters;
            }
            finally
            {
                buf.AsSpan(0, source.Length).Clear();
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        public static RSAParameters FromPkcs8PrivateKey(ReadOnlySpan<byte> source, out int bytesRead)
        {
            throw new NotImplementedException();
        }

        public static RSAParameters FromPkcs8PrivateKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> source, out int bytesRead)
        {
            throw new NotImplementedException();
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
            bool ret = TryWritePkcs1PublicKey(true, Span<byte>.Empty, out int bytesWritten, out byte[] pkcs1);
            Debug.Assert(ret);
            return pkcs1;
        }

        public byte[] ToSubjectPublicKeyInfo()
        {
            bool ret = TryWriteSubjectPublicKeyInfo(true, Span<byte>.Empty, out int bytesWritten, out byte[] spki);
            Debug.Assert(ret);
            return spki;
        }

        public byte[] ToPkcs1PrivateKey()
        {
            bool ret = TryWritePkcs1PrivateKey(true, Span<byte>.Empty, out int bytesWritten, out byte[] pkcs1);
            Debug.Assert(ret);
            return pkcs1;
        }

        public byte[] ToPkcs8PrivateKey()
        {
            bool ret = TryWritePkcs8PrivateKey(true, Span<byte>.Empty, out int bytesWritten, out byte[] pkcs1);
            Debug.Assert(ret);
            return pkcs1;
        }

        public byte[] ToPkcs8PrivateKey(ReadOnlySpan<char> password)
        {
            bool ret = TryWritePkcs8PrivateKey(true, password, Span<byte>.Empty, out int bytesWritten, out byte[] pkcs1);
            Debug.Assert(ret);
            return pkcs1;
        }

        public bool TryWritePkcs1PublicKey(Span<byte> destination, out int bytesWritten)
        {
            return TryWritePkcs1PublicKey(false, destination, out bytesWritten, out _);
        }

        public bool TryWriteSubjectPublicKeyInfo(Span<byte> destination, out int bytesWritten)
        {
            return TryWriteSubjectPublicKeyInfo(false, destination, out bytesWritten, out _);
        }

        public bool TryWritePkcs1PrivateKey(Span<byte> destination, out int bytesWritten)
        {
            return TryWritePkcs1PrivateKey(false, destination, out bytesWritten, out _);
        }

        public bool TryWritePkcs8PrivateKey(Span<byte> destination, out int bytesWritten)
        {
            return TryWritePkcs8PrivateKey(false, destination, out bytesWritten, out _);
        }

        public bool TryWritePkcs8PrivateKey(ReadOnlySpan<char> password, Span<byte> destination, out int bytesWritten)
        {
            return TryWritePkcs8PrivateKey(false, password, destination, out bytesWritten, out _);
        }

        private bool TryWriteSubjectPublicKeyInfo(
            bool createArray,
            Span<byte> destination,
            out int bytesWritten,
            out byte[] createdArray)
        {
            if (Modulus == null || Exponent == null)
            {
                throw new InvalidOperationException(SR.Cryptography_InvalidRsaParameters);
            }

            // If both of Modulus and Exponent had byte lengths in excess of 2^24
            // then they would need 4 length bytes and one "length is 4 bytes" byte each,
            // and the wrapping sequence would need the same.
            // Therefore the maximum amount of overhead we could ever get is 15 (3 * 5),
            // so just go ahead and ask for that much in the temporary buffer for the encoded
            // public key.
            int rentSize = Modulus.Length + Exponent.Length + 15;
            byte[] rented = ArrayPool<byte>.Shared.Rent(rentSize);
            Span<byte> pkcs1PublicKey = Span<byte>.Empty;

            try
            {
                if (!TryWritePkcs1PublicKey(rented, out int ppkSize))
                {
                    Debug.Fail($"Pre-allocated call to TryWritePkcs1PublicKey failed");
                    throw new CryptographicException();
                }

                pkcs1PublicKey = rented.AsSpan(0, ppkSize);

                // https://tools.ietf.org/html/rfc3280#section-4.1
                //
                // SubjectPublicKeyInfo  ::=  SEQUENCE  {
                //   algorithm            AlgorithmIdentifier,
                //   subjectPublicKey     BIT STRING  }
                //
                // https://tools.ietf.org/html/rfc3280#section-4.1.1.2
                //
                // AlgorithmIdentifier  ::=  SEQUENCE  {
                //   algorithm               OBJECT IDENTIFIER,
                //   parameters              ANY DEFINED BY algorithm OPTIONAL  }
                AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

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
                writer.WriteBitString(pkcs1PublicKey);
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
            finally
            {
                pkcs1PublicKey.Clear();
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        private bool TryWritePkcs1PublicKey(
            bool createArray,
            Span<byte> destination,
            out int bytesWritten,
            out byte[] createdArray)
        {
            if (Modulus == null || Exponent == null)
            {
                throw new InvalidOperationException(SR.Cryptography_InvalidRsaParameters);
            }

            BigInteger n = new BigInteger(Modulus, isUnsigned: true, isBigEndian: true);
            BigInteger e = new BigInteger(Exponent, isUnsigned: true, isBigEndian: true);

            using (AsnWriter writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence();
                writer.WriteInteger(n);
                writer.WriteInteger(e);
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

        private bool TryWritePkcs1PrivateKey(
            bool createArray,
            Span<byte> destination,
            out int bytesWritten,
            out byte[] createdArray)
        {
            if (Modulus == null ||
                Exponent == null ||
                D == null ||
                P == null ||
                Q == null ||
                DP == null ||
                DQ == null ||
                InverseQ == null)
            {
                throw new InvalidOperationException(SR.Cryptography_InvalidRsaParameters);
            }

            BigInteger n = new BigInteger(Modulus, isUnsigned: true, isBigEndian: true);
            BigInteger e = new BigInteger(Exponent, isUnsigned: true, isBigEndian: true);
            BigInteger d = new BigInteger(D, isUnsigned: true, isBigEndian: true);
            BigInteger p = new BigInteger(P, isUnsigned: true, isBigEndian: true);
            BigInteger q = new BigInteger(Q, isUnsigned: true, isBigEndian: true);
            BigInteger dp = new BigInteger(DP, isUnsigned: true, isBigEndian: true);
            BigInteger dq = new BigInteger(DQ, isUnsigned: true, isBigEndian: true);
            BigInteger qInv = new BigInteger(InverseQ, isUnsigned: true, isBigEndian: true);

            using (AsnWriter writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence();
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
            throw new NotImplementedException();
        }

        private bool TryWritePkcs8PrivateKey(
            bool createArray,
            ReadOnlySpan<char> password,
            Span<byte> destination,
            out int bytesWritten,
            out byte[] createdArray)
        {
            throw new NotImplementedException();
        }
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
