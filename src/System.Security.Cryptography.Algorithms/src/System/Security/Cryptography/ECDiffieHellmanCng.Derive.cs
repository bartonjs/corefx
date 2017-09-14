// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Security.Permissions;
using System.Diagnostics.Contracts;
using Microsoft.Win32.SafeHandles;

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

            private byte[] DeriveKeyMaterialFromCngKey(ECDiffieHellmanCngPublicKey otherPartyPublicKey) => DeriveKeyFromHash(otherPartyPublicKey, _hashAlgorithm);

            /// <summary>
            ///     Get a handle to the secret agreement generated between two parties
            /// </summary>
            public SafeNCryptSecretHandle DeriveSecretAgreementHandle(ECDiffieHellmanPublicKey otherPartyPublicKey)
            {
                if (otherPartyPublicKey == null)
                {
                    throw new ArgumentNullException("otherPartyPublicKey");
                }

                ECParameters otherPartyParameters = otherPartyPublicKey.ExportParameters();
                using (ECDiffieHellmanCng otherPartyCng = (ECDiffieHellmanCng)Create(otherPartyParameters))
                using (SafeNCryptKeyHandle otherPartyHandle = otherPartyCng.GetDuplicatedKeyHandle())
                {
                    string importedKeyAlgorithmGroup = CngKeyLite.GetPropertyAsString(otherPartyHandle, CngKeyLite.KeyPropertyName.AlgorithmGroup, CngPropertyOptions.None);
                    if (importedKeyAlgorithmGroup == null || importedKeyAlgorithmGroup != "ECDH")
                    {
                        throw new ArgumentException(SR.Cryptography_ArgECDHRequiresECDHKey, "otherPartyPublicKey");
                    }
                    if (CngKeyLite.GetKeyLength(otherPartyHandle) != KeySize)
                    {
                        throw new ArgumentException(SR.Cryptography_ArgECDHKeySizeMismatch, "otherPartyPublicKey");
                    }

                    using (SafeNCryptKeyHandle localHandle = GetDuplicatedKeyHandle())
                    {
                        return Interop.NCrypt.DeriveSecretAgreement(localHandle, otherPartyHandle);
                    }
                }
            }
        }
    }
}
