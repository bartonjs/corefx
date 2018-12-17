﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Text.Json
{
    public enum JsonValueType : byte
    {
        Undefined,
        Object,
        Array,
        String,
        Number,
        True,
        False,
        Null,
    }
}
