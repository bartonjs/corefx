// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;

namespace System.Security.Cryptography
{
    // This enum represents cipher chaining modes: cipher block chaining (CBC), 
    // electronic code book (ECB), and ciphertext-stealing (CTS).  Not all implementations 
    // will support all modes.
    public enum CipherMode
    {
        CBC = 1,
        CTS = 5,
        ECB = 2,

        /// <summary>
        /// Galois/Counter Mode, an Authenticated Encryption (AE) mode.
        /// </summary>
        GCM = 10001,

        /// <summary>
        /// Counter with CBC-MAC mode, an Authenticated Encryption (AE) mode.
        /// </summary>
        CCM = 10002,
    }
}
