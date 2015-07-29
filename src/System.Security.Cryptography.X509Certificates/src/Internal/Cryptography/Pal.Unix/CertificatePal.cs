﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Security.Cryptography.X509Certificates;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class CertificatePal
    {
        public static ICertificatePal FromHandle(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
                throw new ArgumentException(SR.Arg_InvalidHandle, "handle");

            return new OpenSslX509CertificateReader(Interop.libcrypto.X509_dup(handle));
        }

        public static ICertificatePal FromBlob(byte[] rawData, string password, X509KeyStorageFlags keyStorageFlags)
        {
            using (OpenSslPkcs12Reader pfx = OpenSslPkcs12Reader.TryRead(rawData))
            {
                if (pfx != null)
                {
                    pfx.Decrypt(password);

                    ICertificatePal first = null;

                    foreach (OpenSslX509CertificateReader certPal in pfx.ReadCertificates())
                    {
                        // When requesting an X509Certificate2 from a PFX only the first entry is
                        // returned.  Other entries should be disposed.
                        if (first == null)
                        {
                            first = certPal;
                        }
                        else
                        {
                            certPal.Dispose();
                        }
                    }

                    return first;
                }
            }

            return new OpenSslX509CertificateReader(rawData, password);
        }

        public static ICertificatePal FromFile(string fileName, string password, X509KeyStorageFlags keyStorageFlags)
        {
            // Rather than File.ReadAllBytes(fileName) to dispatch into FromBlob, the BIO methods should be used
            // to prevent massive overhead from 'accidentally' passing in a very large non-certificate file.
            throw new NotImplementedException();
        }
    }
}
