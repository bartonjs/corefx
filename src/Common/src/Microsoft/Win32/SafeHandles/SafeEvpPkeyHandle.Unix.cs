// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Microsoft.Win32.SafeHandles
{
    internal sealed class SafeEvpPkeyHandle : SafeHandle
    {
        internal static readonly SafeEvpPkeyHandle InvalidHandle = new SafeEvpPkeyHandle();

        private SafeEvpPkeyHandle() :
            base(IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.libcrypto.EVP_PKEY_free(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        internal static SafeEvpPkeyHandle DuplicateHandle(SafeEvpPkeyHandle handle)
        {
            Debug.Assert(handle != null && !handle.IsInvalid);

            // Reliability: Allocate the SafeHandle before calling UpRefEvpPkey so
            // that we don't lose a tracked reference in low-memory situations.
            SafeEvpPkeyHandle safeHandle = new SafeEvpPkeyHandle();

            if (!Interop.NativeCrypto.UpRefEvpPkey(handle))
            {
                throw Interop.libcrypto.CreateOpenSslCryptographicException();
            }

            // Since we didn't actually create a new handle, copy the handle
            // to the new SafeHandle.
            safeHandle.SetHandle(handle.DangerousGetHandle());
            return safeHandle;
        }
    }
}
