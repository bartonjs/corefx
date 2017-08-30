// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
using static Internal.NativeCrypto.BCryptNative;

namespace System.Security.Cryptography
{
    internal static partial class ECDiffieHellmanImplementation
    {
        public sealed partial class ECDiffieHellmanCng : ECDiffieHellman
        {
            // For the public ECDiffieHellmanCng this is exposed as the HashAlgorithm property
            // which is a CngAlgorithm type. We're not doing that, but we do need the default value
            // for DeriveKeyMaterial.
            private static readonly HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;

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
