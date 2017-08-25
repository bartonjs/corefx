// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.Serialization;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    internal static partial class ECDiffieHellmanImplementation
    {
#endif
        /// <summary>
        /// Public key used to do key exchange with the ECDiffieHellmanCng algorithm
        /// </summary>
        public sealed partial class ECDiffieHellmanCngPublicKey : ECDiffieHellmanPublicKey
        {
            [OptionalField]
            private string _curveName;

            protected override void Dispose(bool disposing)
            {
                base.Dispose(disposing);
            }

            public override string ToXmlString()
            {
                throw new PlatformNotSupportedException();
            }

            public static ECDiffieHellmanCngPublicKey FromXmlString(string xml)
            {
                throw new PlatformNotSupportedException();
            }
        }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
