// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.IO;
using Internal.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    internal static partial class ECDiffieHellmanImplementation
    {
#endif
        public sealed partial class ECDiffieHellmanOpenSsl : ECDiffieHellman
        {
            private ECDiffieHellmanOpenSslPublicKey _key;

            /// <summary>
            /// Create an ECDiffieHellmanOpenSsl algorithm with a named curve.
            /// </summary>
            /// <param name="curve">The <see cref="ECCurve"/> representing the curve.</param>
            /// <exception cref="ArgumentNullException">if <paramref name="curve" /> is null.</exception>
            public ECDiffieHellmanOpenSsl(ECCurve curve) => GenerateKey(curve);

            /// <summary>
            ///     Create an ECDiffieHellmanOpenSsl algorithm with a random 521 bit key pair.
            /// </summary>
            public ECDiffieHellmanOpenSsl() : this(521) { }

            /// <summary>
            ///     Creates a new ECDiffieHellmanOpenSsl object that will use a randomly generated key of the specified size.
            /// </summary>
            /// <param name="keySize">Size of the key to generate, in bits.</param>
            public ECDiffieHellmanOpenSsl(int keySize) => _key = new ECDiffieHellmanOpenSslPublicKey(keySize);

            // Return the three sizes that can be explicitly set (for backwards compatibility)
            public override KeySizes[] LegalKeySizes => new[] {
                new KeySizes(minSize: 256, maxSize: 384, skipSize: 128),
                new KeySizes(minSize: 521, maxSize: 521, skipSize: 0)
            };

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _key.FreeKey();
                }

                base.Dispose(disposing);
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
                        return;

                    // Set the KeySize before FreeKey so that an invalid value doesn't throw away the key
                    base.KeySize = value;
                    _key.SetKey(value);
                }
            }

            public override void GenerateKey(ECCurve curve)
            {
                curve.Validate();
                if (_key != null)
                {
                    _key.FreeKey();
                }

                if (curve.IsNamed)
                {
                    string oid = null;
                    // Use oid Value first if present, otherwise FriendlyName because Oid maintains a hard-coded
                    // cache that may have different casing for FriendlyNames than OpenSsl
                    oid = !string.IsNullOrEmpty(curve.Oid.Value) ? curve.Oid.Value : curve.Oid.FriendlyName;

                    SafeEcKeyHandle keyHandle = Interop.Crypto.EcKeyCreateByOid(oid);

                    if (keyHandle == null || keyHandle.IsInvalid)
                        throw new PlatformNotSupportedException(string.Format(SR.Cryptography_CurveNotSupported, oid));

                    if (!Interop.Crypto.EcKeyGenerateKey(keyHandle))
                        throw Interop.Crypto.CreateOpenSslCryptographicException();

                    SetKey(keyHandle);
                }
                else if (curve.IsExplicit)
                {
                    SafeEcKeyHandle keyHandle = Interop.Crypto.EcKeyCreateByExplicitCurve(curve);

                    if (!Interop.Crypto.EcKeyGenerateKey(keyHandle))
                        throw Interop.Crypto.CreateOpenSslCryptographicException();

                    SetKey(keyHandle);
                }
                else
                {
                    throw new PlatformNotSupportedException(string.Format(SR.Cryptography_CurveNotSupported, curve.CurveType.ToString()));
                }
            }

            /// <summary>
            /// Set the KeySize without validating against LegalKeySizes.
            /// </summary>
            /// <param name="newKeySize">The value to set the KeySize to.</param>
            internal void SetKey(SafeEcKeyHandle keyHandle)
            {
                if (_key == null)
                {
                    _key = new ECDiffieHellmanOpenSslPublicKey(0);
                }
                int newKeySize = _key.SetKey(keyHandle);
                
                // In the event that a key was loaded via ImportParameters, curve name, or an IntPtr/SafeHandle
                // it could be outside of the bounds that we currently represent as "legal key sizes".
                // Since that is our view into the underlying component it can be detached from the
                // component's understanding.  If it said it has opened a key, and this is the size, trust it.
                KeySizeValue = newKeySize;
            }

            public override ECDiffieHellmanPublicKey PublicKey => new ECDiffieHellmanOpenSslPublicKey(_key.DuplicateKeyHandle());

            /// <summary>
            ///         ImportParameters will replace the existing key that ECDiffieHellmanOpenSsl is working with by creating a
            ///         new key. If the parameters contains only Q, then only a public key will be imported.
            ///         If the parameters also contains D, then a full key pair will be imported. 
            ///         The parameters Curve value specifies the type of the curve to import.
            /// </summary>
            /// <param name="parameters">The curve parameters.</param>
            /// <exception cref="CryptographicException">
            ///     if <paramref name="parameters" /> does not contain valid values.
            /// </exception>
            /// <exception cref="NotSupportedException">
            ///     if <paramref name="parameters" /> references a curve that cannot be imported.
            /// </exception>
            /// <exception cref="PlatformNotSupportedException">
            ///     if <paramref name="parameters" /> references a curve that is not supported by this platform.
            /// </exception>
            public override void ImportParameters(ECParameters parameters) => _key.ImportParameters(parameters);

            /// <summary>
            ///     Exports the key and explicit curve parameters used by the ECC object into an <see cref="ECParameters"/> object.
            /// </summary>
            /// <exception cref="CryptographicException">
            ///     if there was an issue obtaining the curve values.
            /// </exception>
            /// <returns>The key and explicit curve parameters used by the ECC object.</returns>
            public override ECParameters ExportExplicitParameters(bool includePrivateParameters) => _key.ExportExplicitParameters(includePrivateParameters);


            /// <summary>
            ///     Exports the key used by the ECC object into an <see cref="ECParameters"/> object.
            ///     If the curve has a name, the Curve property will contain named curve parameters otherwise it will contain explicit parameters.
            /// </summary>
            /// <exception cref="CryptographicException">
            ///     if there was an issue obtaining the curve values.
            /// </exception>
            /// <returns>The key and named curve parameters used by the ECC object.</returns>
            public override ECParameters ExportParameters(bool includePrivateParameters) => _key.ExportParameters(includePrivateParameters);

        }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
