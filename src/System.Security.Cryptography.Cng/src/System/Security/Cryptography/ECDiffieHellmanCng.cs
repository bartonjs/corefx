// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Diagnostics.Contracts;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
    /// <summary>
    ///     Wrapper for CNG's implementation of elliptic curve Diffie-Hellman key exchange
    /// </summary>
    public sealed partial class ECDiffieHellmanCng : ECDiffieHellman
    {
        public ECDiffieHellmanCng(CngKey key)
        {
            Contract.Ensures(LegalKeySizesValue != null);
            Contract.Ensures(_key != null && _key.AlgorithmGroup == CngAlgorithmGroup.ECDiffieHellman);

            if (key == null)
            {
                throw new ArgumentNullException("key");
            }
            if (key.AlgorithmGroup != CngAlgorithmGroup.ECDiffieHellman)
            {
                throw new ArgumentException(SR.Cryptography_ArgECDHRequiresECDHKey, "key");
            }

            LegalKeySizes = s_legalKeySizes;
            // Make a copy of the key so that we continue to work if it gets disposed before this algorithm
            //
            // This requires an assert for UnmanagedCode since we'll need to access the raw handles of the key
            // and the handle constructor of CngKey.  The assert is safe since ECDiffieHellmanCng will never
            // expose the key handles to calling code (without first demanding UnmanagedCode via the Handle
            // property of CngKey).
            //
            // The bizzare looking disposal of the key.Handle property is intentional - Handle returns a
            // duplicate - without disposing it, we keep the key alive until the GC runs.
            //TODO: CAS
            //new SecurityPermission(SecurityPermissionFlag.UnmanagedCode).Assert();
            using (SafeNCryptKeyHandle importHandle = key.Handle)
            {
                Key = CngKey.Open(importHandle, key.IsEphemeral ? CngKeyHandleOpenOptions.EphemeralKey : CngKeyHandleOpenOptions.None);
            }
            //CodeAccessPermission.RevertAssert();

            // Our LegalKeySizes value stores the values that we encoded as being the correct
            // legal key size limitations for this algorithm, as documented on MSDN.
            //
            // But on a new OS version we might not question if our limit is accurate, or MSDN
            // could have been innacurate to start with.
            //
            // Since the key is already loaded, we know that Windows thought it to be valid;
            // therefore we should set KeySizeValue directly to bypass the LegalKeySizes conformance
            // check.
            //
            // For RSA there are known cases where this change matters. RSACryptoServiceProvider can
            // create a 384-bit RSA key, which we consider too small to be legal. It can also create
            // a 1032-bit RSA key, which we consider illegal because it doesn't match our 64-bit
            // alignment requirement. (In both cases Windows loads it just fine)
            KeySizeValue = _key.KeySize;
        }

        internal string GetCurveName()
        {
            return Key.GetCurveName();
        }

        private void ImportFullKeyBlob(byte[] ecfullKeyBlob, bool includePrivateParameters)
        {
            Key = ECCng.ImportFullKeyBlob(ecfullKeyBlob, includePrivateParameters);
        }

        private void ImportKeyBlob(byte[] ecfullKeyBlob, string curveName, bool includePrivateParameters)
        {
            Key = ECCng.ImportKeyBlob(ecfullKeyBlob, curveName, includePrivateParameters);
        }

        private byte[] ExportKeyBlob(bool includePrivateParameters)
        {
            return ECCng.ExportKeyBlob(Key, includePrivateParameters);
        }

        private byte[] ExportFullKeyBlob(bool includePrivateParameters)
        {
            return ECCng.ExportFullKeyBlob(Key, includePrivateParameters);
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

            using (SafeNCryptSecretHandle secretAgreement = DeriveSecretAgreementHandle(otherPartyPublicKey))
            {
                return Interop.NCrypt.DeriveKeyMaterialHash(
                    secretAgreement,
                    hashAlgorithm.Name,
                    secretPrepend,
                    secretAppend,
                    Interop.NCrypt.SecretAgreementFlags.None);
            }
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

            using (SafeNCryptSecretHandle secretAgreement = DeriveSecretAgreementHandle(otherPartyPublicKey))
            {
                Interop.NCrypt.SecretAgreementFlags flags = hmacKey == null ?
                    Interop.NCrypt.SecretAgreementFlags.UseSecretAsHmacKey :
                    Interop.NCrypt.SecretAgreementFlags.None;

                return Interop.NCrypt.DeriveKeyMaterialHmac(
                    secretAgreement,
                    hashAlgorithm.Name,
                    hmacKey,
                    secretPrepend,
                    secretAppend,
                    flags);
            }
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

            using (SafeNCryptSecretHandle secretAgreement = DeriveSecretAgreementHandle(otherPartyPublicKey))
            {
                return Interop.NCrypt.DeriveKeyMaterialTls(
                    secretAgreement,
                    prfLabel,
                    prfSeed,
                    Interop.NCrypt.SecretAgreementFlags.None);
            }
        }
    }
}
