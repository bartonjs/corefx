// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.IO;
using Internal.Cryptography;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics.Contracts;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    internal static partial class ECDiffieHellmanImplementation
    {
#endif
        public sealed partial class ECDiffieHellmanOpenSsl : ECDiffieHellman
        {
            // For the public ECDiffieHellmanCng this is exposed as the HashAlgorithm property
            // which is a CngAlgorithm type. We're not doing that, but we do need the default value
            // for DeriveKeyMaterial.
            private static readonly HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;

            private static byte[] PrependAppendToSecretAgreement(byte[] secretAgreement, byte[] secretPrepend, byte[] secretAppend)
            {
                //TODO: I need to figure out if this is *actually* correct, as the docs are somewhat terse. Add some better tests or research more.
                if (secretAppend == null && secretPrepend == null)
                {
                    return secretAgreement;
                }
                
                int newLength = secretAgreement.Length + (secretPrepend == null ?  0: secretPrepend.Length) + (secretAppend == null ? 0 : secretAppend.Length);
                if (newLength != secretAgreement.Length)
                {
                    byte[] newSecretAgreement = ArrayPool<byte>.Shared.Rent(newLength);
                    int index = 0;
                    if (secretPrepend != null)
                    {
                        Buffer.BlockCopy(secretPrepend, 0, newSecretAgreement, 0, secretPrepend.Length);
                        index += secretPrepend.Length;
                    }
                    Buffer.BlockCopy(secretAgreement, 0, newSecretAgreement, index, secretAgreement.Length);
                    index += secretAgreement.Length;
                    if (secretAppend != null)
                    {
                        Buffer.BlockCopy(secretAppend, 0, newSecretAgreement, index, secretAppend.Length);
                    }
                    return newSecretAgreement;
                }
                return secretAgreement;
            }
            
            /// <summary>
            /// Given a second party's public key, derive shared key material
            /// </summary>
            public override byte[] DeriveKeyMaterial(ECDiffieHellmanPublicKey otherPartyPublicKey) => DeriveKeyFromHash(otherPartyPublicKey, _hashAlgorithm, null, null);

            public override byte[] DeriveKeyFromHash(
                ECDiffieHellmanPublicKey otherPartyPublicKey,
                HashAlgorithmName hashAlgorithm,
                byte[] secretPrepend,
                byte[] secretAppend)
            {
                Contract.Ensures(Contract.Result<byte[]>() != null);

                if (otherPartyPublicKey == null)
                    throw new ArgumentNullException("otherPartyPublicKey");
                if (string.IsNullOrEmpty(hashAlgorithm.Name))
                    throw new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, "hashAlgorithm");

                byte[] secretAgreement = DeriveSecretAgreement(otherPartyPublicKey);
                byte[] modifiedSecretAgreement = PrependAppendToSecretAgreement(secretAgreement, secretPrepend, secretAppend);
                byte[] hashedData = AsymmetricAlgorithmHelpers.HashData(modifiedSecretAgreement, 0, modifiedSecretAgreement.Length, hashAlgorithm);
                ArrayPool<byte>.Shared.Return(secretAgreement);
                ArrayPool<byte>.Shared.Return(modifiedSecretAgreement);
                return hashedData;
            }

            public override byte[] DeriveKeyFromHmac(
                ECDiffieHellmanPublicKey otherPartyPublicKey,
                HashAlgorithmName hashAlgorithm,
                byte[] hmacKey,
                byte[] secretPrepend,
                byte[] secretAppend)
            {
                Contract.Ensures(Contract.Result<byte[]>() != null);

                if (otherPartyPublicKey == null)
                    throw new ArgumentNullException("otherPartyPublicKey");
                if (string.IsNullOrEmpty(hashAlgorithm.Name))
                    throw new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, "hashAlgorithm");

                byte[] secretAgreement = DeriveSecretAgreement(otherPartyPublicKey);
                byte[] modifiedSecretAgreement = PrependAppendToSecretAgreement(secretAgreement, secretPrepend, secretAppend);

                HashProvider hasher = HashProviderDispenser.CreateMacProvider(hashAlgorithm.Name, hmacKey == null ? secretAgreement : hmacKey);
                hasher.AppendHashData(modifiedSecretAgreement, 0, modifiedSecretAgreement.Length);
                byte[] hashedData = hasher.FinalizeHashAndReset();                
                ArrayPool<byte>.Shared.Return(secretAgreement);
                ArrayPool<byte>.Shared.Return(modifiedSecretAgreement);
                return hashedData;
            }

            public override byte[] DeriveKeyTls(ECDiffieHellmanPublicKey otherPartyPublicKey, byte[] prfLabel, byte[] prfSeed)
            {
                Contract.Ensures(Contract.Result<byte[]>() != null);

                if (otherPartyPublicKey == null)
                    throw new ArgumentNullException("otherPartyPublicKey");
                if (prfLabel == null)
                    throw new ArgumentNullException("prfLabel");
                if (prfSeed == null)
                    throw new ArgumentNullException("prfSeed");

                // TODO: do derivation
                throw new PlatformNotSupportedException("OpenSSL does not support DeriveKeyTls.");
            }

            /// <summary>
            /// Get the secret agreement generated between two parties
            /// </summary>
            private byte[] DeriveSecretAgreement(ECDiffieHellmanPublicKey otherPartyPublicKey)
            {
                if (otherPartyPublicKey == null)
                {
                    throw new ArgumentNullException("otherPartyPublicKey");
                }

                ECDiffieHellmanOpenSslPublicKey otherKey = otherPartyPublicKey as ECDiffieHellmanOpenSslPublicKey;
                if (otherKey == null)
                {
                    ECParameters otherPartyParameters = otherPartyPublicKey.ExportParameters();
                    otherKey = new ECDiffieHellmanOpenSslPublicKey(0);
                    otherKey.ImportParameters(otherPartyParameters);
                }

                using (SafeEvpPKeyHandle otherPartyHandle = otherKey.DuplicateKeyHandle())
                {
                    if (otherKey._keySize != _key._keySize)
                    {
                        throw new ArgumentException(SR.Cryptography_ArgECDHKeySizeMismatch, "otherPartyPublicKey");
                    }

                    using (SafeEvpPKeyHandle localHandle = _key.DuplicateKeyHandle())
                    {
                        //return Interop.Crypto.EvpPkeyDeriveSecretAgreement(localHandle, otherPartyHandle);
                        int secretLength;
                        using (SafeEvpPkeyCtxHandle ctx = Interop.Crypto.EvpPkeyCtxCreate(localHandle, otherPartyHandle, out secretLength))
                        {
                            byte[] secret = ArrayPool<Byte>.Shared.Rent(secretLength);
                            Interop.Crypto.EvpPkeyDeriveSecretAgreement(secret, secretLength, ctx);
                            return secret;
                        }
                    }
                }
            }
        }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
