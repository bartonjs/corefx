// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Security.Permissions;
using System.Diagnostics.Contracts;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
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

            // We can only work with ECDiffieHellmanCngPublicKeys
            ECDiffieHellmanCngPublicKey otherKey = otherPartyPublicKey as ECDiffieHellmanCngPublicKey;
            if (otherPartyPublicKey == null)
            {
                throw new ArgumentException(SR.Cryptography_ArgExpectedECDiffieHellmanCngPublicKey);
            }

            using (CngKey import = otherKey.Import())
            {
                return DeriveKeyMaterial(import);
            }
        }

        /// <summary>
        ///     Given a second party's public key, derive shared key material
        /// </summary>
        public byte[] DeriveKeyMaterial(CngKey otherPartyPublicKey)
        {
            Contract.Ensures(Contract.Result<byte[]>() != null);
            Contract.Assert(_kdf >= ECDiffieHellmanKeyDerivationFunction.Hash &&
                            _kdf <= ECDiffieHellmanKeyDerivationFunction.Tls);

            if (otherPartyPublicKey == null)
            {
                throw new ArgumentNullException("otherPartyPublicKey");
            }
            if (otherPartyPublicKey.AlgorithmGroup != CngAlgorithmGroup.ECDiffieHellman)
            {
                throw new ArgumentException(SR.Cryptography_ArgECDHRequiresECDHKey, "otherPartyPublicKey");
            }
            if (otherPartyPublicKey.KeySize != KeySize)
            {
                throw new ArgumentException(SR.Cryptography_ArgECDHKeySizeMismatch, "otherPartyPublicKey");
            }

            Interop.NCrypt.SecretAgreementFlags flags =
                UseSecretAgreementAsHmacKey ? Interop.NCrypt.SecretAgreementFlags.UseSecretAsHmacKey : Interop.NCrypt.SecretAgreementFlags.None;

            // This looks horribly wrong - but accessing the handle property actually returns a duplicate handle, which
            // we need to dispose of - otherwise, we're stuck keepign the resource alive until the GC runs.  This explicitly
            // is not disposing of the handle underlying the key dispite what the syntax looks like.
            using (SafeNCryptKeyHandle localKey = Key.Handle)
            using (SafeNCryptKeyHandle otherKey = otherPartyPublicKey.Handle)
            {
                // Generating key material is a two phase process.
                //   1. Generate the secret agreement
                //   2. Pass the secret agreement through a KDF to get key material

                using (SafeNCryptSecretHandle secretAgreement = Interop.NCrypt.DeriveSecretAgreement(localKey, otherKey))
                {
                    if (KeyDerivationFunction == ECDiffieHellmanKeyDerivationFunction.Hash)
                    {
                        byte[] secretAppend = SecretAppend == null ? null : SecretAppend.Clone() as byte[];
                        byte[] secretPrepend = SecretPrepend == null ? null : SecretPrepend.Clone() as byte[];

                        return Interop.NCrypt.DeriveKeyMaterialHash(secretAgreement,
                                                                    HashAlgorithm.Algorithm,
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
                                                                    HashAlgorithm.Algorithm,
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

            // We can only work with ECDiffieHellmanCngPublicKeys
            ECDiffieHellmanCngPublicKey otherKey = otherPartyPublicKey as ECDiffieHellmanCngPublicKey;
            if (otherPartyPublicKey == null)
            {
                throw new ArgumentException(SR.Cryptography_ArgExpectedECDiffieHellmanCngPublicKey);
            }

            using (CngKey importedKey = otherKey.Import())
            {
                return DeriveSecretAgreementHandle(importedKey);
            }
        }

        /// <summary>
        ///     Get a handle to the secret agreement between two parties
        /// </summary>
        public SafeNCryptSecretHandle DeriveSecretAgreementHandle(CngKey otherPartyPublicKey)
        {
            if (otherPartyPublicKey == null)
            {
                throw new ArgumentNullException("otherPartyPublicKey");
            }
            if (otherPartyPublicKey.AlgorithmGroup != CngAlgorithmGroup.ECDiffieHellman)
            {
                throw new ArgumentException(SR.Cryptography_ArgECDHRequiresECDHKey, "otherPartyPublicKey");
            }
            if (otherPartyPublicKey.KeySize != KeySize)
            {
                throw new ArgumentException(SR.Cryptography_ArgECDHKeySizeMismatch, "otherPartyPublicKey");
            }

            // This looks strange, but the Handle property returns a duplicate so we need to dispose of it when we're done
            using (SafeNCryptKeyHandle localHandle = Key.Handle)
            using (SafeNCryptKeyHandle otherPartyHandle = otherPartyPublicKey.Handle)
            {
                return Interop.NCrypt.DeriveSecretAgreement(localHandle, otherPartyHandle);
            }
        }
    }
}
