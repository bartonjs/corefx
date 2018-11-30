// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Text.Json
{
    public partial class JsonDocument
    {
        // This is the subset JsonTokenType which is stored in the processed data database.
        // The subsetting is required because the database only allocates 3 bits to this
        // value, and JsonTokenType has more than 8 values.
        //
        // String to Null match in order with JsonTokenType, and are mapped between the two
        // types by addition.
        internal enum JsonType
        {
            StartObject,
            StartArray,
            String,
            Number,
            True,
            False,
            Null,
        }
    }
}
