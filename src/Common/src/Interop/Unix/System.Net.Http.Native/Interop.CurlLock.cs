// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Threading;

internal static partial class Interop
{
    internal static partial class Http
    {
        private static object s_conditionalLock;

        internal static void SetLockInterop()
        {
            object existingLock = Interlocked.Exchange(ref s_conditionalLock, new object());
            Debug.Assert(existingLock == null, $"{nameof(SetLockInterop)} was called twice");
        }

        internal struct CurlLock : IDisposable
        {
            private object _heldMonitor;

            internal static CurlLock Enter()
            {
                object monitor = s_conditionalLock;

                CurlLock curlLock;
                curlLock._heldMonitor = monitor;

                if (monitor != null)
                {
                    Monitor.Enter(monitor);
                }

                return curlLock;
            }

            public void Dispose()
            {
                Debug.Assert(_heldMonitor == s_conditionalLock, "_heldMonitor is not s_conditionalLock");

                if (_heldMonitor != null)
                {
                    Monitor.Exit(_heldMonitor);
                }
            }
        }
    }
}