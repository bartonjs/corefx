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
            /// <summary>
            ///     Given a second party's public key, derive shared key material
            /// </summary>
            public override byte[] DeriveKeyMaterial(ECDiffieHellmanPublicKey otherPartyPublicKey)
            {
                Contract.Ensures(Contract.Result<byte[]>() != null);
                Contract.Assert(_kdf >= ECDiffieHellmanKeyDerivationFunction.Hash &&
                                _kdf <= ECDiffieHellmanKeyDerivationFunction.Tls);

                if (otherPartyPublicKey == null)
                {
                    throw new ArgumentNullException("otherPartyPublicKey");
                }

                ECParameters otherPartyParameters = otherPartyPublicKey.ExportParameters();
                using (ECDiffieHellmanCng otherPartyCng = (ECDiffieHellmanCng)Create(otherPartyParameters)) //TODO: catch this if it fails and throw exception that the otherpartyPublicKey must be CNG
                using (SafeNCryptKeyHandle otherKey = otherPartyCng.GetDuplicatedKeyHandle())
                {
                    string importedKeyAlgorithmGroup = CngKeyLite.GetPropertyAsString(otherKey, CngKeyLite.KeyPropertyName.AlgorithmGroup, CngPropertyOptions.None);
                    if (importedKeyAlgorithmGroup == null || importedKeyAlgorithmGroup != "ECDH")
                    {
                        throw new ArgumentException(SR.Cryptography_ArgECDHRequiresECDHKey, "otherPartyPublicKey");
                    }
                    if (CngKeyLite.GetKeyLength(otherKey) != KeySize)
                    {
                        throw new ArgumentException(SR.Cryptography_ArgECDHKeySizeMismatch, "otherPartyPublicKey");
                    }

                    Interop.NCrypt.SecretAgreementFlags flags =
                        UseSecretAgreementAsHmacKey ? Interop.NCrypt.SecretAgreementFlags.UseSecretAsHmacKey : Interop.NCrypt.SecretAgreementFlags.None;

                    using (SafeNCryptKeyHandle localKey = GetDuplicatedKeyHandle())
                    using (SafeNCryptSecretHandle secretAgreement = Interop.NCrypt.DeriveSecretAgreement(localKey, otherKey))
                    {
                        if (KeyDerivationFunction == ECDiffieHellmanKeyDerivationFunction.Hash)
                        {
                            byte[] secretAppend = SecretAppend == null ? null : SecretAppend.Clone() as byte[];
                            byte[] secretPrepend = SecretPrepend == null ? null : SecretPrepend.Clone() as byte[];

                            return Interop.NCrypt.DeriveKeyMaterialHash(secretAgreement,
                                                                        _hashAlgorithm.Name,
                                                                        secretPrepend,
                                                                        secretAppend,
                                                                        flags);
                        }
                        else if (KeyDerivationFunction == ECDiffieHellmanKeyDerivationFunction.Hmac)
                        {
                            byte[] hmacKey = HmacKey == null ? null : HmacKey.Clone() as byte[];
                            byte[] secretAppend = SecretAppend == null ? null : SecretAppend.Clone() as byte[];
                            byte[] secretPrepend = SecretPrepend == null ? null : SecretPrepend.Clone() as byte[];

                            return Interop.NCrypt.DeriveKeyMaterialHmac(secretAgreement,
                                                                        _hashAlgorithm.Name,
                                                                        hmacKey,
                                                                        secretPrepend,
                                                                        secretAppend,
                                                                        flags);
                        }
                        else
                        {
                            Debug.Assert(KeyDerivationFunction == ECDiffieHellmanKeyDerivationFunction.Tls, "Unknown KDF");

                            byte[] label = Label == null ? null : Label.Clone() as byte[];
                            byte[] seed = Seed == null ? null : Seed.Clone() as byte[];

                            if (label == null || seed == null)
                            {
                                throw new InvalidOperationException(SR.Cryptography_TlsRequiresLabelAndSeed);
                            }

                            return Interop.NCrypt.DeriveKeyMaterialTls(secretAgreement, label, seed, flags);
                        }
                    }
                }
            }

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
                using (ECDiffieHellmanCng otherPartyCng = (ECDiffieHellmanCng)Create(otherPartyParameters)) //TODO: catch this if it fails and throw exception that the otherpartyPublicKey must be CNG
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
