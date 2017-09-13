// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Internal.Cryptography;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    internal static partial class ECDiffieHellmanImplementation
    {
#endif
        internal sealed partial class ECDiffieHellmanOpenSslPublicKey : ECDiffieHellmanPublicKey
        {
            private Lazy<SafeEcKeyHandle> _key;
            internal int _keySize;

            /// <summary>
            /// Create an ECDiffieHellmanOpenSslPublicKey from an <see cref="SafeEvpPKeyHandle"/> whose value is an existing
            /// OpenSSL <c>EVP_PKEY*</c> wrapping an <c>EC_KEY*</c>
            /// </summary>
            /// <param name="pkeyHandle">A SafeHandle for an OpenSSL <c>EVP_PKEY*</c></param>
            /// <exception cref="ArgumentNullException"><paramref name="pkeyHandle"/> is <c>null</c></exception>
            /// <exception cref="ArgumentException"><paramref name="pkeyHandle"/> <see cref="SafeHandle.IsInvalid" /></exception>
            /// <exception cref="CryptographicException"><paramref name="pkeyHandle"/> is not a valid enveloped <c>EC_KEY*</c></exception>
            internal ECDiffieHellmanOpenSslPublicKey(SafeEvpPKeyHandle pkeyHandle)
            {
                if (pkeyHandle == null)
                    throw new ArgumentNullException(nameof(pkeyHandle));
                if (pkeyHandle.IsInvalid)
                    throw new ArgumentException(SR.Cryptography_OpenInvalidHandle, nameof(pkeyHandle));

                // If ecKey is valid it has already been up-ref'd, so we can just use this handle as-is.
                SafeEcKeyHandle key = Interop.Crypto.EvpPkeyGetEcKey(pkeyHandle);
                if (key.IsInvalid)
                {
                    key.Dispose();
                    throw Interop.Crypto.CreateOpenSslCryptographicException();
                }

                SetKey(key);
            }

            /// <summary>
            /// Create an ECDiffieHellmanOpenSslPublicKey from an existing <see cref="IntPtr"/> whose value is an
            /// existing OpenSSL <c>EC_KEY*</c>.
            /// </summary>
            /// <remarks>
            /// This method will increase the reference count of the <c>EC_KEY*</c>, the caller should
            /// continue to manage the lifetime of their reference.
            /// </remarks>
            /// <param name="handle">A pointer to an OpenSSL <c>EC_KEY*</c></param>
            /// <exception cref="ArgumentException"><paramref name="handle" /> is invalid</exception>
            public ECDiffieHellmanOpenSslPublicKey(IntPtr handle)
            {
                if (handle == IntPtr.Zero)
                    throw new ArgumentException(SR.Cryptography_OpenInvalidHandle, nameof(handle));

                SafeEcKeyHandle ecKeyHandle = SafeEcKeyHandle.DuplicateHandle(handle);
                SetKey(ecKeyHandle);
            }

            internal ECDiffieHellmanOpenSslPublicKey(int keySize) => SetKey(keySize);

            public override string ToXmlString()
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

            internal void ImportParameters(ECParameters parameters) => SetKey(ECOpenSsl.ImportParameters(parameters));
            public override ECParameters ExportExplicitParameters() => ECOpenSsl.ExportExplicitParameters(_key.Value, includePrivateParameters: false);
            internal ECParameters ExportExplicitParameters(bool includePrivateParameters) => ECOpenSsl.ExportExplicitParameters(_key.Value, includePrivateParameters);
            public override ECParameters ExportParameters() => ECOpenSsl.ExportParameters(_key.Value, includePrivateParameters: false);
            internal ECParameters ExportParameters(bool includePrivateParameters) => ECOpenSsl.ExportParameters(_key.Value, includePrivateParameters);

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    FreeKey();
                }

                base.Dispose(disposing);
            }

            /// <summary>
            /// Obtain a SafeHandle version of an EVP_PKEY* which wraps an EC_KEY* equivalent
            /// to the current key for this instance.
            /// </summary>
            /// <returns>A SafeHandle for the EC_KEY key in OpenSSL</returns>
            internal SafeEvpPKeyHandle DuplicateKeyHandle()
            {
                if (_key == null)
                    throw new ObjectDisposedException("TODO this");

                SafeEcKeyHandle currentKey = _key.Value;
                Debug.Assert(currentKey != null, "null TODO");

                SafeEvpPKeyHandle pkeyHandle = Interop.Crypto.EvpPkeyCreate();

                try
                {
                    // Wrapping our key in an EVP_PKEY will up_ref our key.
                    // When the EVP_PKEY is Disposed it will down_ref the key.
                    // So everything should be copacetic.
                    if (!Interop.Crypto.EvpPkeySetEcKey(pkeyHandle, currentKey))
                    {
                        throw Interop.Crypto.CreateOpenSslCryptographicException();
                    }

                    return pkeyHandle;
                }
                catch
                {
                    pkeyHandle.Dispose();
                    throw;
                }
            }

            private SafeEcKeyHandle GenerateKeyLazy() => ECOpenSsl.GenerateKeyByKeySize(_keySize);


            internal void FreeKey()
            {
                if (_key != null)
                {
                    if (_key.IsValueCreated)
                    {
                        SafeEcKeyHandle handle = _key.Value;
                        if (handle != null)
                            handle.Dispose();
                    }
                    _key = null;
                }
            }

            internal int SetKey(SafeEcKeyHandle newKey)
            {
                _keySize = Interop.Crypto.EcKeyGetSize(newKey);
                _key = new Lazy<SafeEcKeyHandle>(newKey);
                return _keySize;
            }

            internal void SetKey(int keySize)
            {
                if (_keySize == keySize)
                    return;

                FreeKey();
                _keySize = keySize;
                _key = new Lazy<SafeEcKeyHandle>(GenerateKeyLazy);
            }
        }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
