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
        public byte[] D;
        public byte[] DP;
        public byte[] DQ;
        public byte[] Exponent;
        public byte[] InverseQ;
        public byte[] Modulus;
        public byte[] P;
        public byte[] Q;
    }
}
