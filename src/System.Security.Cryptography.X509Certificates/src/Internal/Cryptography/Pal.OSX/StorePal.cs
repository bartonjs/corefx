// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Apple;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class StorePal
    {
        public static IStorePal FromHandle(IntPtr storeHandle)
        {
            throw new PlatformNotSupportedException();
        }

        public static ILoaderPal FromBlob(byte[] rawData, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
        {
            Debug.Assert(password != null);

            SafeTemporaryKeychainHandle tmpKeychain = Interop.AppleCrypto.CreateTemporaryKeychain();

            try
            {
                SafeCFArrayHandle certs = Interop.AppleCrypto.X509ImportCollection(rawData, password, tmpKeychain);
                return new AppleCertLoader(certs, tmpKeychain);
            }
            catch
            {
                tmpKeychain.Dispose();
                throw;
            }
        }

        public static ILoaderPal FromFile(string fileName, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
        {
            Debug.Assert(password != null);

            byte[] fileBytes = System.IO.File.ReadAllBytes(fileName);
            return FromBlob(fileBytes, password, keyStorageFlags);
        }

        public static IExportPal FromCertificate(ICertificatePal cert)
        {
            return new AppleCertificateExporter(cert);
        }

        public static IExportPal LinkFromCertificateCollection(X509Certificate2Collection certificates)
        {
            return new AppleCertificateExporter(certificates);
        }

        public static IStorePal FromSystemStore(string storeName, StoreLocation storeLocation, OpenFlags openFlags)
        {
            StringComparer ordinalIgnoreCase = StringComparer.OrdinalIgnoreCase;

            switch (storeLocation)
            {
                case StoreLocation.CurrentUser:
                    if (ordinalIgnoreCase.Equals("My", storeName))
                        return AppleKeychainStore.OpenDefaultKeychain();

                    break;
                case StoreLocation.LocalMachine:
                    if (ordinalIgnoreCase.Equals("My", storeName))
                        return AppleKeychainStore.OpenSystemSharedKeychain();
                    if (ordinalIgnoreCase.Equals("Root", storeName))
                        return AppleKeychainStore.OpenSystemRootsKeychain();

                    break;
            }

            throw new NotImplementedException();
        }

        private sealed class AppleKeychainStore : IStorePal
        {
            private SafeKeychainHandle _keychainHandle;

            public AppleKeychainStore(SafeKeychainHandle keychainHandle)
            {
                Debug.Assert(keychainHandle != null && !keychainHandle.IsInvalid);

                _keychainHandle = keychainHandle;
            }

            public void Dispose()
            {
                _keychainHandle?.Dispose();
                _keychainHandle = null;
            }

            public void CloneTo(X509Certificate2Collection collection)
            {
                HashSet<X509Certificate2> dedupedCerts = new HashSet<X509Certificate2>();

                using (SafeCFArrayHandle identities = Interop.AppleCrypto.KeychainEnumerateIdentities(_keychainHandle))
                {
                    ReadCollection(identities, dedupedCerts);
                }

                using (SafeCFArrayHandle certs = Interop.AppleCrypto.KeychainEnumerateCerts(_keychainHandle))
                {
                    ReadCollection(certs, dedupedCerts);
                }

                foreach (X509Certificate2 cert in dedupedCerts)
                {
                    collection.Add(cert);
                }
            }

            private static void ReadCollection(SafeCFArrayHandle matches, HashSet<X509Certificate2> collection)
            {
                if (matches.IsInvalid)
                {
                    return;
                }

                long count = Interop.CoreFoundation.CFArrayGetCount(matches);

                for (int i = 0; i < count; i++)
                {
                    IntPtr handle = Interop.CoreFoundation.CFArrayGetValueAtIndex(matches, i);

                    SafeSecCertificateHandle certHandle;
                    SafeSecIdentityHandle identityHandle;

                    if (Interop.AppleCrypto.X509DemuxAndRetainHandle(handle, out certHandle, out identityHandle))
                    {
                        X509Certificate2 cert;

                        if (certHandle.IsInvalid)
                        {
                            certHandle.Dispose();
                            cert = new X509Certificate2(new AppleCertificatePal(identityHandle));
                        }
                        else
                        {
                            identityHandle.Dispose();
                            cert = new X509Certificate2(new AppleCertificatePal(certHandle));
                        }

                        if (!collection.Add(cert))
                        {
                            cert.Dispose();
                        }
                    }
                }
            }

            public void Add(ICertificatePal cert)
            {
                throw new NotImplementedException();
            }

            public void Remove(ICertificatePal cert)
            {
                throw new NotImplementedException();
            }

            public SafeHandle SafeHandle => _keychainHandle;

            public static AppleKeychainStore OpenDefaultKeychain()
            {
                return new AppleKeychainStore(Interop.AppleCrypto.SecKeychainCopyDefault());
            }

            public static AppleKeychainStore OpenSystemSharedKeychain()
            {
                const string SharedSystemKeychainPath = "/Library/Keychains/System.keychain";
                return OpenKeychain(SharedSystemKeychainPath);
            }

            public static AppleKeychainStore OpenSystemRootsKeychain()
            {
                const string SystemRootKeychainPath =
                    "/System/Library/Keychains/SystemRootCertificates.keychain";

                return OpenKeychain(SystemRootKeychainPath);
            }

            private static AppleKeychainStore OpenKeychain(string keychainPath)
            {
                return new AppleKeychainStore(Interop.AppleCrypto.SecKeychainOpen(keychainPath));
            }
        }
    }
}
