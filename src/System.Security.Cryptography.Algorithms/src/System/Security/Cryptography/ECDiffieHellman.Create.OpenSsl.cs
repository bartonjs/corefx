// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
    public abstract partial class ECDiffieHellman : AsymmetricAlgorithm
    {
        /// <summary>
        /// Creates an instance of the platform specific implementation of the cref="ECDiffieHellman" algorithm.
        /// </summary>
        public static new ECDiffieHellman Create()
        {
            return new ECDiffieHellmanImplementation.ECDiffieHellmanOpenSsl();
        }

        /// <summary>
        /// Creates a new instance of the default implementation of the Elliptic Curve Diffie-Hellman Algorithm
        /// (ECDH) with a newly generated key over the specified curve.
        /// </summary>
        /// <param name="curve">The curve to use for key generation.</param>
        /// <returns>A new instance of the default implementation of this class.</returns>
        public static ECDiffieHellman Create(ECCurve curve)
        {
            return new ECDiffieHellmanImplementation.ECDiffieHellmanOpenSsl(curve);
        }

        /// <summary>
        /// Creates a new instance of the default implementation of the Elliptic Curve Diffie-Hellman Algorithm
        /// (ECDH) using the specified ECParameters as the key.
        /// </summary>
        /// <param name="parameters">The parameters representing the key to use.</param>
        /// <returns>A new instance of the default implementation of this class.</returns>
        public static ECDiffieHellman Create(ECParameters parameters)
        {
            ECDiffieHellman ecdh = new ECDiffieHellmanImplementation.ECDiffieHellmanOpenSsl();
            ecdh.ImportParameters(parameters);
            return ecdh;
        }
    }
}
