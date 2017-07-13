// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class Http
    {
        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_MultiCreate")]
        private static extern SafeCurlMultiHandle HttpNative_MultiCreate();

        public static SafeCurlMultiHandle MultiCreate()
        {
            using (CurlLock.Enter())
            {
                return HttpNative_MultiCreate();
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_MultiDestroy")]
        private static extern CURLMcode HttpNative_MultiDestroy(IntPtr handle);

        private static CURLMcode MultiDestroy(IntPtr handle)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_MultiDestroy(handle);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_MultiAddHandle")]
        private static extern CURLMcode HttpNative_MultiAddHandle(SafeCurlMultiHandle multiHandle, SafeCurlHandle easyHandle);

        public static CURLMcode MultiAddHandle(SafeCurlMultiHandle multiHandle, SafeCurlHandle easyHandle)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_MultiAddHandle(multiHandle, easyHandle);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_MultiRemoveHandle")]
        private static extern CURLMcode HttpNative_MultiRemoveHandle(SafeCurlMultiHandle multiHandle, SafeCurlHandle easyHandle);

        public static CURLMcode MultiRemoveHandle(SafeCurlMultiHandle multiHandle, SafeCurlHandle easyHandle)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_MultiRemoveHandle(multiHandle, easyHandle);
            }
        }

        // Locking this one seems bad.
        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_MultiWait")]
        public static extern CURLMcode MultiWait(
            SafeCurlMultiHandle multiHandle,
            SafeFileHandle extraFileDescriptor,
            out bool isExtraFileDescriptorActive,
            out bool isTimeout);

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_MultiPerform")]
        private static extern CURLMcode HttpNative_MultiPerform(SafeCurlMultiHandle multiHandle);

        public static CURLMcode MultiPerform(SafeCurlMultiHandle multiHandle)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_MultiPerform(multiHandle);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_MultiInfoRead")]
        private static extern bool HttpNative_MultiInfoRead(
            SafeCurlMultiHandle multiHandle,
            out CURLMSG message,
            out IntPtr easyHandle,
            out CURLcode result);

        public static bool MultiInfoRead(
            SafeCurlMultiHandle multiHandle,
            out CURLMSG message,
            out IntPtr easyHandle,
            out CURLcode result)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_MultiInfoRead(multiHandle, out message, out easyHandle, out result);
            }
        }

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_MultiGetErrorString")]
        public static extern IntPtr MultiGetErrorString(int code);

        [DllImport(Libraries.HttpNative, EntryPoint = "HttpNative_MultiSetOptionLong")]
        private static extern CURLMcode HttpNative_MultiSetOptionLong(SafeCurlMultiHandle curl, CURLMoption option, long value);

        public static CURLMcode MultiSetOptionLong(SafeCurlMultiHandle curl, CURLMoption option, long value)
        {
            using (CurlLock.Enter())
            {
                return HttpNative_MultiSetOptionLong(curl, option, value);
            }
        }

        // Enum for constants defined for the enum CURLMcode in multi.h
        internal enum CURLMcode : int
        {
            CURLM_CALL_MULTI_PERFORM = -1,
            CURLM_OK = 0,
            CURLM_BAD_HANDLE = 1,
            CURLM_BAD_EASY_HANDLE = 2,
            CURLM_OUT_OF_MEMORY = 3,
            CURLM_INTERNAL_ERROR = 4,
            CURLM_BAD_SOCKET = 5,
            CURLM_UNKNOWN_OPTION = 6,
            CURLM_ADDED_ALREADY = 7,
        }

        internal enum CURLMoption : int
        {
            CURLMOPT_PIPELINING = 3,
            CURLMOPT_MAX_HOST_CONNECTIONS = 7,
        }

        internal enum CurlPipe : int
        {
            CURLPIPE_MULTIPLEX = 2
        }

        // Enum for constants defined for the enum CURLMSG in multi.h
        internal enum CURLMSG : int
        {
            CURLMSG_DONE = 1,
        }

        internal sealed class SafeCurlMultiHandle : SafeHandle
        {
            public SafeCurlMultiHandle()
                : base(IntPtr.Zero, true)
            {
            }

            public override bool IsInvalid
            {
                get { return this.handle == IntPtr.Zero; }
            }

            protected override bool ReleaseHandle()
            {
                using (CurlLock.Enter())
                {
                    bool result = MultiDestroy(handle) == CURLMcode.CURLM_OK;
                    SetHandle(IntPtr.Zero);
                    return result;
                }
            }
        }
    }
}
