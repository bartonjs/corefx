// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Numerics;
using System.Runtime.InteropServices;

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
