// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    internal static partial class ECDiffieHellmanImplementation
    {
#endif
        public sealed partial class ECDiffieHellmanOpenSslPublicKey : ECDiffieHellmanPublicKey
        {
            private ECParameters _parameters;
            private ECParameters _explicitParameters;

            protected override void Dispose(bool disposing)
            {
                base.Dispose(disposing);
            }

            public override string ToXmlString()
            {
                throw new PlatformNotSupportedException();
            }

            public static ECDiffieHellmanOpenSslPublicKey FromXmlString(string xml)
            {
                throw new PlatformNotSupportedException();
            }

            /// <summary>
            /// There is no key blob format for OpenSSL ECDH like there is for Cng ECDH. Instead of allowing
            /// this to return a potentially confusing empty byte array, we opt to throw instead. 
            /// </summary>
            public override byte[] ToByteArray()
            {
                throw new PlatformNotSupportedException();
            }

            internal ECDiffieHellmanOpenSslPublicKey(ECParameters parameters, ECParameters explicitParameters)
            {
                _parameters = parameters;
                _explicitParameters = explicitParameters;
            }

            /// <summary>
            ///  Exports the key and explicit curve parameters used by the ECC object into an <see cref="ECParameters"/> object.
            /// </summary>
            /// <returns>The key and explicit curve parameters used by the ECC object.</returns>
            public override ECParameters ExportExplicitParameters()
            {
                return _explicitParameters;
            }

            /// <summary>
            ///  Exports the key used by the ECC object into an <see cref="ECParameters"/> object.
            ///  If the key was created as a named curve, the Curve property will contain named curve parameters
            ///  otherwise it will contain explicit parameters.
            /// </summary>
            /// <returns>The key and named curve parameters used by the ECC object.</returns>
            public override ECParameters ExportParameters()
            {
                return _parameters;
            }
        }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
