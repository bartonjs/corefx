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

        public static RSAParameters FromPkcs1PublicKey(ReadOnlySpan<byte> source, out int bytesRead)
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(source.Length);
            source.CopyTo(buf);

            try
            {
                RSAPublicKey publicKey =
                    AsnSerializer.Deserialize<RSAPublicKey>(buf, AsnEncodingRules.BER, out int read);

                RSAParameters rsaParameters = new RSAParameters()
                {
                    Modulus = publicKey.Modulus.ToByteArray(isUnsigned: true, isBigEndian: true),
                    Exponent = publicKey.PublicExponent.ToByteArray(isUnsigned: true, isBigEndian: true),
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

                RSAParameters rsaParameters = new RSAParameters()
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

        public byte[] ToPkcs1PrivateKey()
        {
            bool ret = TryWritePkcs1PrivateKey(true, Span<byte>.Empty, out int bytesWritten, out byte[] pkcs1);
            Debug.Assert(ret);
            return pkcs1;
        }

        public bool TryWritePkcs1PublicKey(Span<byte> destination, out int bytesWritten)
        {
            return TryWritePkcs1PublicKey(false, destination, out bytesWritten, out _);
        }

        public bool TryWritePkcs1PrivateKey(Span<byte> destination, out int bytesWritten)
        {
            return TryWritePkcs1PrivateKey(false, destination, out bytesWritten, out _);
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
