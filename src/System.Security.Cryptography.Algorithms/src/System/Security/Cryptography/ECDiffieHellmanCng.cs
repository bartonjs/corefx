// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
using static Internal.NativeCrypto.BCryptNative;

namespace System.Security.Cryptography
{
    public abstract partial class ECDiffieHellman : AsymmetricAlgorithm
    {
        /// <summary>
        /// Creates an instance of the platform specific implementation of the cref="ECDiffieHellman" algorithm.
        /// </summary>
        public static new ECDiffieHellman Create()
        {
            return new ECDiffieHellmanImplementation.ECDiffieHellmanCng();
        }

        /// <summary>
        /// Creates a new instance of the default implementation of the Elliptic Curve Diffie-Hellman Algorithm
        /// (ECDH) with a newly generated key over the specified curve.
        /// </summary>
        /// <param name="curve">The curve to use for key generation.</param>
        /// <returns>A new instance of the default implementation of this class.</returns>
        public static ECDiffieHellman Create(ECCurve curve)
        {
            return new ECDiffieHellmanImplementation.ECDiffieHellmanCng(curve);
        }

        /// <summary>
        /// Creates a new instance of the default implementation of the Elliptic Curve Diffie-Hellman Algorithm
        /// (ECDH) using the specified ECParameters as the key.
        /// </summary>
        /// <param name="parameters">The parameters representing the key to use.</param>
        /// <returns>A new instance of the default implementation of this class.</returns>
        public static ECDiffieHellman Create(ECParameters parameters)
        {
            ECDiffieHellman ecdh = new ECDiffieHellmanImplementation.ECDiffieHellmanCng();
            ecdh.ImportParameters(parameters);
            return ecdh;
        }
    }

    internal static partial class ECDiffieHellmanImplementation
    {
        public sealed partial class ECDiffieHellmanCng : ECDiffieHellman
        {
            private void ImportFullKeyBlob(byte[] ecfullKeyBlob, bool includePrivateParameters)
            {
                string blobType = includePrivateParameters ?
                    Interop.BCrypt.KeyBlobType.BCRYPT_ECCFULLPRIVATE_BLOB :
                    Interop.BCrypt.KeyBlobType.BCRYPT_ECCFULLPUBLIC_BLOB;

                SafeNCryptKeyHandle keyHandle = CngKeyLite.ImportKeyBlob(blobType, ecfullKeyBlob);

                Debug.Assert(!keyHandle.IsInvalid);

                _keyHandle = keyHandle;
                _lastAlgorithm = AlgorithmName.ECDH;

                int newKeySize = CngKeyLite.GetKeyLength(keyHandle);

                ForceSetKeySize(newKeySize);
                _lastKeySize = newKeySize;
            }

            private void ImportKeyBlob(byte[] ecKeyBlob, string curveName, bool includePrivateParameters)
            {
                string blobType = includePrivateParameters ?
                    Interop.BCrypt.KeyBlobType.BCRYPT_ECCPRIVATE_BLOB :
                    Interop.BCrypt.KeyBlobType.BCRYPT_ECCPUBLIC_BLOB;

                SafeNCryptKeyHandle keyHandle = CngKeyLite.ImportKeyBlob(blobType, ecKeyBlob, curveName);

                Debug.Assert(!keyHandle.IsInvalid);

                _keyHandle = keyHandle;
                _lastAlgorithm = ECCng.EcdhCurveNameToAlgorithm(curveName);

                int newKeySize = CngKeyLite.GetKeyLength(keyHandle);

                ForceSetKeySize(newKeySize);
                _lastKeySize = newKeySize;
            }

            private byte[] ExportKeyBlob(bool includePrivateParameters)
            {
                string blobType = includePrivateParameters ?
                    Interop.BCrypt.KeyBlobType.BCRYPT_ECCPRIVATE_BLOB :
                    Interop.BCrypt.KeyBlobType.BCRYPT_ECCPUBLIC_BLOB;

                using (SafeNCryptKeyHandle keyHandle = GetDuplicatedKeyHandle())
                {
                    return CngKeyLite.ExportKeyBlob(keyHandle, blobType);
                }
            }

            private byte[] ExportFullKeyBlob(bool includePrivateParameters)
            {
                string blobType = includePrivateParameters ?
                    Interop.BCrypt.KeyBlobType.BCRYPT_ECCFULLPRIVATE_BLOB :
                    Interop.BCrypt.KeyBlobType.BCRYPT_ECCFULLPUBLIC_BLOB;

                using (SafeNCryptKeyHandle keyHandle = GetDuplicatedKeyHandle())
                {
                    return CngKeyLite.ExportKeyBlob(keyHandle, blobType);
                }
            }
        }
    }
}
