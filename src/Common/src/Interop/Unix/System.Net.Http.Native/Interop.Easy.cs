// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Http
    {
        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_EasyCreate")]
        private static extern SafeCurlHandle HttpNative_EasyCreate();

        public static SafeCurlHandle EasyCreate()
        {
            using (CurlLock.Enter())
            {
                return HttpNative_EasyCreate();
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_EasyDestroy")]
        private static extern void HttpNative_EasyDestroy(IntPtr handle);

        private static void EasyDestroy(IntPtr handle)
        {
            using (CurlLock.Enter())
            {
                HttpNative_EasyDestroy(handle);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_EasySetOptionString", CharSet = CharSet.Ansi)]
        private static extern CURLcode HttpNative_EasySetOptionString(SafeCurlHandle curl, CURLoption option, string value);

        public static CURLcode EasySetOptionString(SafeCurlHandle curl, CURLoption option, string value)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_EasySetOptionString(curl, option, value);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_EasySetOptionLong")]
        private static extern CURLcode HttpNative_EasySetOptionLong(SafeCurlHandle curl, CURLoption option, long value);

        public static CURLcode EasySetOptionLong(SafeCurlHandle curl, CURLoption option, long value)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_EasySetOptionLong(curl, option, value);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_EasySetOptionPointer")]
        private static extern CURLcode HttpNative_EasySetOptionPointer(SafeCurlHandle curl, CURLoption option, IntPtr value);

        public static CURLcode EasySetOptionPointer(SafeCurlHandle curl, CURLoption option, IntPtr value)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_EasySetOptionPointer(curl, option, value);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_EasySetOptionPointer")]
        private static extern CURLcode HttpNative_EasySetOptionPointer(SafeCurlHandle curl, CURLoption option, SafeHandle value);

        public static CURLcode EasySetOptionPointer(SafeCurlHandle curl, CURLoption option, SafeHandle value)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_EasySetOptionPointer(curl, option, value);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_EasyGetErrorString")]
        public static extern IntPtr EasyGetErrorString(int code);

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_EasyGetInfoPointer")]
        private static extern CURLcode HttpNative_EasyGetInfoPointer(IntPtr handle, CURLINFO info, out IntPtr value);

        public static CURLcode EasyGetInfoPointer(IntPtr handle, CURLINFO info, out IntPtr value)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_EasyGetInfoPointer(handle, info, out value);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_EasyGetInfoPointer")]
        private static extern CURLcode HttpNative_EasyGetInfoPointer(SafeCurlHandle handle, CURLINFO info, out IntPtr value);

        public static CURLcode EasyGetInfoPointer(SafeCurlHandle handle, CURLINFO info, out IntPtr value)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_EasyGetInfoPointer(handle, info, out value);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_EasyGetInfoLong")]
        private static extern CURLcode HttpNative_EasyGetInfoLong(SafeCurlHandle handle, CURLINFO info, out long value);

        public static CURLcode EasyGetInfoLong(SafeCurlHandle handle, CURLINFO info, out long value)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_EasyGetInfoLong(handle, info, out value);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_EasyPerform")]
        private static extern CURLcode HttpNative_EasyPerform(SafeCurlHandle curl);

        public static CURLcode EasyPerform(SafeCurlHandle curl)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_EasyPerform(curl);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_EasyUnpause")]
        public static extern CURLcode EasyUnpause(SafeCurlHandle easy);

        public delegate CurlSeekResult SeekCallback(IntPtr userPointer, long offset, int origin);

        public delegate ulong ReadWriteCallback(IntPtr buffer, ulong bufferSize, ulong nitems, IntPtr userPointer);

        public delegate CURLcode SslCtxCallback(IntPtr curl, IntPtr sslCtx, IntPtr userPointer);

        public delegate void DebugCallback(IntPtr curl, CurlInfoType type, IntPtr data, ulong size, IntPtr userPointer);

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_RegisterSeekCallback")]
        private static extern void HttpNative_RegisterSeekCallback(
            SafeCurlHandle curl,
            SeekCallback callback,
            IntPtr userPointer,
            ref SafeCallbackHandle callbackHandle);

        public static void RegisterSeekCallback(
            SafeCurlHandle curl,
            SeekCallback callback,
            IntPtr userPointer,
            ref SafeCallbackHandle callbackHandle)
        {
            using (CurlLock.Enter())
            {
                HttpNative_RegisterSeekCallback(curl, callback, userPointer, ref callbackHandle);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_RegisterReadWriteCallback")]
        private static extern void HttpNative_RegisterReadWriteCallback(
            SafeCurlHandle curl,
            ReadWriteFunction functionType,
            ReadWriteCallback callback,
            IntPtr userPointer,
            ref SafeCallbackHandle callbackHandle);

        public static void RegisterReadWriteCallback(
            SafeCurlHandle curl,
            ReadWriteFunction functionType,
            ReadWriteCallback callback,
            IntPtr userPointer,
            ref SafeCallbackHandle callbackHandle)
        {
            using (CurlLock.Enter())
            {
                HttpNative_RegisterReadWriteCallback(curl, functionType, callback, userPointer, ref callbackHandle);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_RegisterSslCtxCallback")]
        private static extern CURLcode HttpNative_RegisterSslCtxCallback(
            SafeCurlHandle curl,
            SslCtxCallback callback,
            IntPtr userPointer,
            ref SafeCallbackHandle callbackHandle);

        public static CURLcode RegisterSslCtxCallback(
            SafeCurlHandle curl,
            SslCtxCallback callback,
            IntPtr userPointer,
            ref SafeCallbackHandle callbackHandle)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_RegisterSslCtxCallback(curl, callback, userPointer, ref callbackHandle);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_RegisterDebugCallback")]
        private static extern CURLcode HttpNative_RegisterDebugCallback(
            SafeCurlHandle curl,
            DebugCallback callback,
            IntPtr userPointer,
            ref SafeCallbackHandle callbackHandle);

        public static CURLcode RegisterDebugCallback(
            SafeCurlHandle curl,
            DebugCallback callback,
            IntPtr userPointer,
            ref SafeCallbackHandle callbackHandle)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_RegisterDebugCallback(curl, callback, userPointer, ref callbackHandle);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_FreeCallbackHandle")]
        private static extern void HttpNative_FreeCallbackHandle(IntPtr handle);

        private static void FreeCallbackHandle(IntPtr handle)
        {
            using (CurlLock.Enter())
            {
                HttpNative_FreeCallbackHandle(handle);
            }
        }

        // Curl options are of the format <type base> + <n>
        private const int CurlOptionLongBase = 0;
        private const int CurlOptionObjectPointBase = 10000;
        private const int CurlOptionOffTBase = 30000;

        // Enum for constants defined for the enum CURLoption in curl.h
        internal enum CURLoption
        {
            CURLOPT_INFILESIZE = CurlOptionLongBase + 14,
            CURLOPT_SSLVERSION = CurlOptionLongBase + 32,
            CURLOPT_VERBOSE = CurlOptionLongBase + 41,
            CURLOPT_NOBODY = CurlOptionLongBase + 44,
            CURLOPT_UPLOAD = CurlOptionLongBase + 46,
            CURLOPT_POST = CurlOptionLongBase + 47,
            CURLOPT_FOLLOWLOCATION = CurlOptionLongBase + 52,
            CURLOPT_PROXYPORT = CurlOptionLongBase + 59,
            CURLOPT_POSTFIELDSIZE = CurlOptionLongBase + 60,
            CURLOPT_SSL_VERIFYPEER = CurlOptionLongBase + 64,
            CURLOPT_MAXREDIRS = CurlOptionLongBase + 68,
            CURLOPT_SSL_VERIFYHOST = CurlOptionLongBase + 81,
            CURLOPT_HTTP_VERSION = CurlOptionLongBase + 84,
            CURLOPT_DNS_CACHE_TIMEOUT = CurlOptionLongBase + 92,
            CURLOPT_NOSIGNAL = CurlOptionLongBase + 99,
            CURLOPT_PROXYTYPE = CurlOptionLongBase + 101,
            CURLOPT_HTTPAUTH = CurlOptionLongBase + 107,
            CURLOPT_TCP_NODELAY = CurlOptionLongBase + 121,
            CURLOPT_CONNECTTIMEOUT_MS = CurlOptionLongBase + 156,
            CURLOPT_ADDRESS_SCOPE = CurlOptionLongBase + 171,
            CURLOPT_PROTOCOLS = CurlOptionLongBase + 181,
            CURLOPT_REDIR_PROTOCOLS = CurlOptionLongBase + 182,

            CURLOPT_URL = CurlOptionObjectPointBase + 2,
            CURLOPT_PROXY = CurlOptionObjectPointBase + 4,
            CURLOPT_PROXYUSERPWD = CurlOptionObjectPointBase + 6,
            CURLOPT_COOKIE = CurlOptionObjectPointBase + 22,
            CURLOPT_HTTPHEADER = CurlOptionObjectPointBase + 23,
            CURLOPT_CUSTOMREQUEST = CurlOptionObjectPointBase + 36,
            CURLOPT_ACCEPT_ENCODING = CurlOptionObjectPointBase + 102,
            CURLOPT_PRIVATE = CurlOptionObjectPointBase + 103,
            CURLOPT_COPYPOSTFIELDS = CurlOptionObjectPointBase + 165,
            CURLOPT_USERNAME = CurlOptionObjectPointBase + 173,
            CURLOPT_PASSWORD = CurlOptionObjectPointBase + 174,

            CURLOPT_INFILESIZE_LARGE = CurlOptionOffTBase + 115,
            CURLOPT_POSTFIELDSIZE_LARGE = CurlOptionOffTBase + 120,
        }

        internal enum ReadWriteFunction
        {
            Write = 0,
            Read = 1,
            Header = 2,
        }

        // Curl info are of the format <type base> + <n>
        private const int CurlInfoStringBase = 0x100000;
        private const int CurlInfoLongBase = 0x200000;

        // Enum for constants defined for CURL_HTTP_VERSION
        internal enum CurlHttpVersion
        {
            CURL_HTTP_VERSION_NONE = 0,
            CURL_HTTP_VERSION_1_0 = 1,
            CURL_HTTP_VERSION_1_1 = 2,
            CURL_HTTP_VERSION_2_0 = 3,
        };

        // Enum for constants defined for CURL_SSLVERSION
        internal enum CurlSslVersion
        {
            CURL_SSLVERSION_TLSv1 = 1,   /* TLS 1.x */
            CURL_SSLVERSION_TLSv1_0 = 4, /* TLS 1.0 */
            CURL_SSLVERSION_TLSv1_1 = 5, /* TLS 1.1 */
            CURL_SSLVERSION_TLSv1_2 = 6, /* TLS 1.2 */
        };

        // Enum for constants defined for the enum CURLINFO in curl.h
        internal enum CURLINFO
        {
            CURLINFO_EFFECTIVE_URL = CurlInfoStringBase + 1,
            CURLINFO_PRIVATE = CurlInfoStringBase + 21,
            CURLINFO_HTTPAUTH_AVAIL = CurlInfoLongBase + 23,
        }

        // AUTH related constants
        [Flags]
        internal enum CURLAUTH
        {
            None = 0,
            Basic = 1 << 0,
            Digest = 1 << 1,
            Negotiate = 1 << 2,
            NTLM = 1 << 3,
        }

        // Enum for constants defined for the enum curl_proxytype in curl.h
        internal enum curl_proxytype
        {
            CURLPROXY_HTTP = 0,
        }

        [Flags]
        internal enum CurlProtocols
        {
            CURLPROTO_HTTP = (1 << 0),
            CURLPROTO_HTTPS = (1 << 1),
        }

        // Enum for constants defined for the results of CURL_SEEKFUNCTION
        internal enum CurlSeekResult : int
        {
            CURL_SEEKFUNC_OK = 0,
            CURL_SEEKFUNC_FAIL = 1,
            CURL_SEEKFUNC_CANTSEEK = 2,
        }

        internal enum CurlInfoType : int
        {
            CURLINFO_TEXT = 0,
            CURLINFO_HEADER_IN = 1,
            CURLINFO_HEADER_OUT = 2,
            CURLINFO_DATA_IN = 3,
            CURLINFO_DATA_OUT = 4,
            CURLINFO_SSL_DATA_IN = 5,
            CURLINFO_SSL_DATA_OUT = 6,
        };

        // constants defined for the results of a CURL_READ or CURL_WRITE function
        internal const ulong CURL_READFUNC_ABORT = 0x10000000;
        internal const ulong CURL_READFUNC_PAUSE = 0x10000001;
        internal const ulong CURL_WRITEFUNC_PAUSE = 0x10000001;

        internal const ulong CURL_MAX_HTTP_HEADER = 100 * 1024;

        internal sealed class SafeCurlHandle : SafeHandle
        {
            public SafeCurlHandle() : base(IntPtr.Zero, true)
            {
            }

            public override bool IsInvalid
            {
                get { return handle == IntPtr.Zero; }
            }

            protected override bool ReleaseHandle()
            {
                using (CurlLock.Enter())
                {
                    EasyDestroy(handle);
                    SetHandle(IntPtr.Zero);
                    return true;
                }
            }
        }

        internal sealed class SafeCallbackHandle : SafeHandle
        {
            public SafeCallbackHandle()
                : base(IntPtr.Zero, true)
            {
            }

            public override bool IsInvalid
            {
                get { return handle == IntPtr.Zero; }
            }

            protected override bool ReleaseHandle()
            {
                FreeCallbackHandle(handle);
                SetHandle(IntPtr.Zero);
                return true;
            }
        }
    }
}
