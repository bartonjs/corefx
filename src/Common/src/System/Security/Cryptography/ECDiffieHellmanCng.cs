// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Diagnostics.Contracts;
using static Internal.NativeCrypto.BCryptNative;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    internal static partial class ECDiffieHellmanImplementation
    {
#endif
        /// <summary>
        ///     Wrapper for CNG's implementation of elliptic curve Diffie-Hellman key exchange
        /// </summary>
        public sealed partial class ECDiffieHellmanCng : ECDiffieHellman
        {
            private static KeySizes[] s_legalKeySizes = new KeySizes[] { new KeySizes(256, 384, 128), new KeySizes(521, 521, 0) };

            public ECDiffieHellmanCng() : this(521) { }

            public ECDiffieHellmanCng(int keySize)
            {
                KeySize = keySize;
            }

            public ECDiffieHellmanCng(ECCurve curve)
            {
                // GenerateKey will already do all of the validation we need.
                GenerateKey(curve);
            }

            public override int KeySize
            {
                get
                {
                    return base.KeySize;
                }
                set
                {
                    if (KeySize == value)
                    {
                        return;
                    }

                    // Set the KeySize before DisposeKey so that an invalid value doesn't throw away the key
                    base.KeySize = value;

                    DisposeKey();

                    // Key will be lazily re-created
                }
            }

            /// <summary>
            /// Set the KeySize without validating against LegalKeySizes.
            /// </summary>
            /// <param name="newKeySize">The value to set the KeySize to.</param>
            private void ForceSetKeySize(int newKeySize)
            {
                // In the event that a key was loaded via ImportParameters, curve name, or an IntPtr/SafeHandle
                // it could be outside of the bounds that we currently represent as "legal key sizes".
                // Since that is our view into the underlying component it can be detached from the
                // component's understanding.  If it said it has opened a key, and this is the size, trust it.
                KeySizeValue = newKeySize;
            }

            /// <summary>
            /// Given a second party's public key, derive shared key material
            /// </summary>
            public override byte[] DeriveKeyMaterial(ECDiffieHellmanPublicKey otherPartyPublicKey)
            {
                Contract.Ensures(Contract.Result<byte[]>() != null);

                if (otherPartyPublicKey == null)
                {
                    throw new ArgumentNullException("otherPartyPublicKey");
                }

                ECDiffieHellmanCngPublicKey otherKey = otherPartyPublicKey as ECDiffieHellmanCngPublicKey;
                if (otherKey == null)
                {
                    // We may be able to create a CngPublicKey from the otherPartyPublicKey. Note that this is a change from previous
                    // netfx behavior where a failed cast results in a CryptoException immediately. This is to account for when the 
                    // otherPartyPublicKey was created by ECDiffieHellman.Create().PublicKey in which case the type is the internal
                    // Algorithms ECDiffieHellmanCngPublicKey implementation.
                    ECParameters otherPartyParameters = otherPartyPublicKey.ExportParameters();
                    using (ECDiffieHellmanCng otherPartyCng = new ECDiffieHellmanCng())
                    {
                        try
                        {
                            // If the otherkey doesn't represent an object that can be loaded as a CNG key then ImportParameters throws a CryptoException.
                            otherPartyCng.ImportParameters(otherPartyParameters);
                            otherKey = otherPartyCng.PublicKey as ECDiffieHellmanCngPublicKey;
                        }
                        catch (CryptographicException)
                        {
                            throw new ArgumentException(SR.Cryptography_ArgExpectedECDiffieHellmanCngPublicKey);
                        }
                    }
                }

                return DeriveKeyMaterialFromCngKey(otherKey);
            }

            public override KeySizes[] LegalKeySizes
            {
                get
                {
                    // Return the three sizes that can be explicitly set (for backwards compatibility)
                    return new[] {
                        new KeySizes(minSize: 256, maxSize: 384, skipSize: 128),
                        new KeySizes(minSize: 521, maxSize: 521, skipSize: 0),
                    };
                }
            }
        }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
