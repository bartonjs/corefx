// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using Internal.NativeCrypto;

internal static partial class Interop
{
    internal static partial class NCrypt
    {
        /// <summary>
        ///     Generate a key from a secret agreement
        /// </summary>
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern ErrorCode NCryptDeriveKey(SafeNCryptSecretHandle hSharedSecret,
                                                        string pwszKDF,
                                                        [In] ref NCryptBufferDesc pParameterList,
                                                        [Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbDerivedKey,
                                                        int cbDerivedKey,
                                                        [Out] out int pcbResult,
                                                        SecretAgreementFlags dwFlags);

        /// <summary>
        ///     Derive key material from a hash or HMAC KDF
        /// </summary>
        /// <returns></returns>
        [System.Security.SecurityCritical]
        private static byte[] DeriveKeyMaterial(SafeNCryptSecretHandle secretAgreement,
                                                string kdf,
                                                string hashAlgorithm,
                                                byte[] hmacKey,
                                                byte[] secretPrepend,
                                                byte[] secretAppend,
                                                SecretAgreementFlags flags)
        {
            Contract.Requires(secretAgreement != null);
            Contract.Requires(!String.IsNullOrEmpty(kdf));
            Contract.Requires(!String.IsNullOrEmpty(hashAlgorithm));
            Contract.Requires(hmacKey == null || kdf == BCryptNative.KeyDerivationFunction.Hmac);
            Contract.Ensures(Contract.Result<byte[]>() != null);

            List<NCryptBuffer> parameters = new List<NCryptBuffer>();

            // First marshal the hash algoritm
            IntPtr hashAlgorithmString = IntPtr.Zero;

            // Run in a CER so that we know we'll free the memory for the marshaled string
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                // Assign in a CER so we don't fail between allocating the memory and assigning the result
                // back to the string variable.
                RuntimeHelpers.PrepareConstrainedRegions();
                try { }
                finally
                {
                    hashAlgorithmString = Marshal.StringToCoTaskMemUni(hashAlgorithm);
                }

                // We always need to marshal the hashing function
                NCryptBuffer hashAlgorithmBuffer = new NCryptBuffer();
                hashAlgorithmBuffer.cbBuffer = (hashAlgorithm.Length + 1) * sizeof(char);
                hashAlgorithmBuffer.BufferType = BufferType.KdfHashAlgorithm;
                hashAlgorithmBuffer.pvBuffer = hashAlgorithmString;
                parameters.Add(hashAlgorithmBuffer);

                unsafe
                {
                    fixed (byte* pHmacKey = hmacKey, pSecretPrepend = secretPrepend, pSecretAppend = secretAppend)
                    {
                        //
                        // Now marshal the other parameters
                        //

                        if (pHmacKey != null)
                        {
                            NCryptBuffer hmacKeyBuffer = new NCryptBuffer();
                            hmacKeyBuffer.cbBuffer = hmacKey.Length;
                            hmacKeyBuffer.BufferType = BufferType.KdfHmacKey;
                            hmacKeyBuffer.pvBuffer = new IntPtr(pHmacKey);
                            parameters.Add(hmacKeyBuffer);
                        }

                        if (pSecretPrepend != null)
                        {
                            NCryptBuffer secretPrependBuffer = new NCryptBuffer();
                            secretPrependBuffer.cbBuffer = secretPrepend.Length;
                            secretPrependBuffer.BufferType = BufferType.KdfSecretPrepend;
                            secretPrependBuffer.pvBuffer = new IntPtr(pSecretPrepend);
                            parameters.Add(secretPrependBuffer);
                        }

                        if (pSecretAppend != null)
                        {
                            NCryptBuffer secretAppendBuffer = new NCryptBuffer();
                            secretAppendBuffer.cbBuffer = secretAppend.Length;
                            secretAppendBuffer.BufferType = BufferType.KdfSecretAppend;
                            secretAppendBuffer.pvBuffer = new IntPtr(pSecretAppend);
                            parameters.Add(secretAppendBuffer);
                        }

                        return DeriveKeyMaterial(secretAgreement,
                                                 kdf,
                                                 parameters.ToArray(),
                                                 flags);
                    }
                }
            }
            finally
            {
                if (hashAlgorithmString != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(hashAlgorithmString);
                }
            }
        }

        /// <summary>
        ///     Derive key material using a given KDF and secret agreement
        /// </summary>
        [System.Security.SecurityCritical]
        private static byte[] DeriveKeyMaterial(SafeNCryptSecretHandle secretAgreement,
                                                string kdf,
                                                NCryptBuffer[] parameters,
                                                SecretAgreementFlags flags)
        {
            Contract.Requires(secretAgreement != null);
            Contract.Requires(!String.IsNullOrEmpty(kdf));
            Contract.Requires(parameters != null);
            Contract.Ensures(Contract.Result<byte[]>() != null);

            unsafe
            {
                fixed (NCryptBuffer* pParameters = parameters)
                {
                    NCryptBufferDesc parameterDesc = new NCryptBufferDesc();
                    parameterDesc.ulVersion = 0;
                    parameterDesc.cBuffers = parameters.Length;
                    parameterDesc.pBuffers = new IntPtr(pParameters);

                    // Figure out how big the key material is
                    int keySize = 0;
                    ErrorCode error = NCryptDeriveKey(secretAgreement,
                                                                          kdf,
                                                                          ref parameterDesc,
                                                                          null,
                                                                          0,
                                                                          out keySize,
                                                                          flags);
                    if (error != ErrorCode.ERROR_SUCCESS && error != ErrorCode.NTE_BUFFER_TOO_SMALL)
                    {
                        throw new CryptographicException((int)error);
                    }

                    // Allocate memory for the key material and generate it
                    byte[] keyMaterial = new byte[keySize];
                    error = NCryptDeriveKey(secretAgreement,
                                                                kdf,
                                                                ref parameterDesc,
                                                                keyMaterial,
                                                                keyMaterial.Length,
                                                                out keySize,
                                                                flags);

                    if (error != ErrorCode.ERROR_SUCCESS)
                    {
                        throw new CryptographicException((int)error);
                    }

                    return keyMaterial;
                }
            }
        }

        /// <summary>
        ///     Derive key material from a secret agreement using a hash KDF
        /// </summary>
        [System.Security.SecurityCritical]
        internal static byte[] DeriveKeyMaterialHash(SafeNCryptSecretHandle secretAgreement,
                                                     string hashAlgorithm,
                                                     byte[] secretPrepend,
                                                     byte[] secretAppend,
                                                     SecretAgreementFlags flags)
        {
            Contract.Requires(secretAgreement != null);
            Contract.Requires(!String.IsNullOrEmpty(hashAlgorithm));
            Contract.Ensures(Contract.Result<byte[]>() != null);

            return DeriveKeyMaterial(secretAgreement,
                                     BCryptNative.KeyDerivationFunction.Hash,
                                     hashAlgorithm,
                                     null,
                                     secretPrepend,
                                     secretAppend,
                                     flags);
        }

        /// <summary>
        ///     Derive key material from a secret agreement using a HMAC KDF
        /// </summary>
        [System.Security.SecurityCritical]
        internal static byte[] DeriveKeyMaterialHmac(SafeNCryptSecretHandle secretAgreement,
                                                     string hashAlgorithm,
                                                     byte[] hmacKey,
                                                     byte[] secretPrepend,
                                                     byte[] secretAppend,
                                                     SecretAgreementFlags flags)
        {
            Contract.Requires(secretAgreement != null);
            Contract.Requires(!String.IsNullOrEmpty(hashAlgorithm));
            Contract.Ensures(Contract.Result<byte[]>() != null);

            return DeriveKeyMaterial(secretAgreement,
                                     BCryptNative.KeyDerivationFunction.Hmac,
                                     hashAlgorithm,
                                     hmacKey,
                                     secretPrepend,
                                     secretAppend,
                                     flags);
        }

        /// <summary>
        ///     Derive key material from a secret agreeement using the TLS KDF
        /// </summary>
        [System.Security.SecurityCritical]
        internal static byte[] DeriveKeyMaterialTls(SafeNCryptSecretHandle secretAgreement,
                                                    byte[] label,
                                                    byte[] seed,
                                                    SecretAgreementFlags flags)
        {
            Contract.Requires(secretAgreement != null);
            Contract.Requires(label != null && seed != null);
            Contract.Ensures(Contract.Result<byte[]>() != null);

            NCryptBuffer[] buffers = new NCryptBuffer[2];

            unsafe
            {
                fixed (byte* pLabel = label, pSeed = seed)
                {
                    NCryptBuffer labelBuffer = new NCryptBuffer();
                    labelBuffer.cbBuffer = label.Length;
                    labelBuffer.BufferType = BufferType.KdfTlsLabel;
                    labelBuffer.pvBuffer = new IntPtr(pLabel);
                    buffers[0] = labelBuffer;

                    NCryptBuffer seedBuffer = new NCryptBuffer();
                    seedBuffer.cbBuffer = seed.Length;
                    seedBuffer.BufferType = BufferType.KdfTlsSeed;
                    seedBuffer.pvBuffer = new IntPtr(pSeed);
                    buffers[1] = seedBuffer;

                    return DeriveKeyMaterial(secretAgreement,
                                             BCryptNative.KeyDerivationFunction.Tls,
                                             buffers,
                                             flags);
                }
            }
        }

    }
}
