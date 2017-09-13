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

                //TODO: this may not make sense anymore for openssl
                ECDiffieHellmanOpenSslPublicKey otherKey = otherPartyPublicKey as ECDiffieHellmanOpenSslPublicKey;
                if (otherKey == null)
                {
                    // We may be able to create a ECDiffieHellmanOpenSslPublicKey from the otherPartyPublicKey. Note that this is a change from previous
                    // netfx behavior where a failed cast results in a CryptoException immediately. This is to account for when the 
                    // otherPartyPublicKey was created by ECDiffieHellman.Create().PublicKey in which case the type is the internal
                    // Algorithms ECDiffieHellmanOpenSslPublicKey implementation.
                    ECParameters otherPartyParameters = otherPartyPublicKey.ExportParameters();
                    using (ECDiffieHellmanOpenSsl otherPartyOpenSsl = new ECDiffieHellmanOpenSsl())
                    {
                        try
                        {
                            // If the otherkey doesn't represent an object that can be loaded as a openssl key then ImportParameters throws a CryptoException.
                            otherPartyOpenSsl.ImportParameters(otherPartyParameters);
                            otherKey = otherPartyOpenSsl.PublicKey as ECDiffieHellmanOpenSslPublicKey;
                        }
                        catch (CryptographicException)
                        {
                            throw new ArgumentException(/* TODO ADD SR SR.Cryptography_ArgExpectedECDiffieHellmanOpenSslPublicKey */);
                        }
                    }
                }

                // TODO: do derivation
                throw new NotImplementedException();
            }

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

                // TODO: do derivation
                //using (SafeNCryptSecretHandle secretAgreement = DeriveSecretAgreementHandle(otherPartyPublicKey))
                //{
                //    return Interop.NCrypt.DeriveKeyMaterialHash(
                //        secretAgreement,
                //        hashAlgorithm.Name,
                //        secretPrepend,
                //        secretAppend,
                //        Interop.NCrypt.SecretAgreementFlags.None);
                //}
                throw new NotImplementedException();
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

                // TODO: do derivation
                //using (SafeNCryptSecretHandle secretAgreement = DeriveSecretAgreementHandle(otherPartyPublicKey))
                //{
                //    Interop.NCrypt.SecretAgreementFlags flags = hmacKey == null ?
                //        Interop.NCrypt.SecretAgreementFlags.UseSecretAsHmacKey :
                //        Interop.NCrypt.SecretAgreementFlags.None;

                //    return Interop.NCrypt.DeriveKeyMaterialHmac(
                //        secretAgreement,
                //        hashAlgorithm.Name,
                //        hmacKey,
                //        secretPrepend,
                //        secretAppend,
                //        flags);
                throw new NotImplementedException();
            //}
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
        }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
