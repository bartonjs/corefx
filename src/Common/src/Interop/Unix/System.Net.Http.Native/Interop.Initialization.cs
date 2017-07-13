// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    // Initialization of libcurl is done in a static constructor.
    // This enables a project simply to include this file, and any usage of any of
    // the Http functions will trigger initialization.
    
    internal static partial class Http
    {
        static Http()
        {
            HttpInitializer.Initialize();
        }
    }

    internal static class HttpInitializer
    {
        static HttpInitializer()
        {
            string curlSslVersion = Interop.Http.GetSslVersionDescription();

            if (string.IsNullOrEmpty(curlSslVersion) ||
                curlSslVersion.IndexOf(Interop.Http.OpenSsl10Description, StringComparison.OrdinalIgnoreCase) != -1)
            {
#if !SYSNETHTTP_NO_OPENSSL
                // CURL uses OpenSSL which me must initialize first to guarantee thread-safety
                // Only initialize for OpenSSL/1.0, any newer versions may have mismatched
                // pointers, resulting in segfaults.
                CryptoInitializer.Initialize();
#else
                Http.SetLockInterop();
#endif
            }
            else if (curlSslVersion.IndexOf(Http.LibreSslDescription, StringComparison.OrdinalIgnoreCase) != -1)
            {
                Http.SetLockInterop();
            }

            if (EnsureCurlIsInitialized() != 0)
            {
                throw new InvalidOperationException();
            }
        }

        internal static void Initialize()
        {
            // No-op that exists to provide a hook for other static constructors
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_EnsureCurlIsInitialized")]
        private static extern int EnsureCurlIsInitialized();
    }
}
