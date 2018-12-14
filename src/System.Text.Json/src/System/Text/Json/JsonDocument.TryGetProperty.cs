﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Diagnostics;

namespace System.Text.Json
{
    public sealed partial class JsonDocument
    {
        internal bool TryGetNamedPropertyValue(int index, ReadOnlySpan<char> propertyName, out JsonElement value)
        {
            CheckNotDisposed();

            _parsedData.Get(index, out DbRow row);

            CheckExpectedType(JsonTokenType.StartObject, row.TokenType);

            if (row.NumberOfRows == 0)
            {
                value = default;
                return false;
            }

            int maxBytes = Utf8JsonReader.Utf8Encoding.GetMaxByteCount(propertyName.Length);
            int endIndex = checked(row.NumberOfRows * DbRow.Size + index);

            // The biggest number of bytes we're willing to pre-UTF8
            const int StackUtf8Max = 256;

            if (maxBytes < StackUtf8Max)
            {
                Span<byte> utf8Name = stackalloc byte[StackUtf8Max];
                int len = Utf8JsonReader.Utf8Encoding.GetBytes(propertyName, utf8Name);
                utf8Name = utf8Name.Slice(0, len);

                return TryGetNamedPropertyValue(
                    index + DbRow.Size,
                    endIndex,
                    utf8Name,
                    out value);
            }

            // Unescaping the property name will make the string shorter (or the same)
            // So the first viable candidate is one whose length in bytes matches, or
            // exceeds, our length in chars.
            //
            // The maximal escaping seems to be 6 -> 1 ("\u0030" => "0"), but just transcode
            // and switch once one viable long property is found.

            int minBytes = propertyName.Length;
            int candidateIndex = index + DbRow.Size;

            while (candidateIndex < endIndex)
            {
                _parsedData.Get(candidateIndex, out row);
                Debug.Assert(row.TokenType == JsonTokenType.PropertyName);

                if (row.SizeOrLength >= minBytes)
                {
                    byte[] tmpUtf8 = ArrayPool<byte>.Shared.Rent(maxBytes);
                    Span<byte> utf8Name = default;

                    try
                    {
                        int len = Utf8JsonReader.Utf8Encoding.GetBytes(propertyName, tmpUtf8);
                        utf8Name = tmpUtf8.AsSpan(0, len);

                        return TryGetNamedPropertyValue(
                            candidateIndex,
                            endIndex,
                            utf8Name,
                            out value);
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(tmpUtf8);
                    }
                }

                // Move to the value
                candidateIndex += DbRow.Size;
                _parsedData.Get(candidateIndex, out row);

                // Move past the value
                if (row.IsSimpleValue)
                {
                    candidateIndex += DbRow.Size;
                }
                else
                {
                    candidateIndex += DbRow.Size * (row.NumberOfRows + 1);
                }
            }

            // None of the property names were within the range that the UTF-8 encoding would have been.
            value = default;
            return false;
        }

        internal bool TryGetNamedPropertyValue(int index, ReadOnlySpan<byte> propertyName, out JsonElement value)
        {
            CheckNotDisposed();

            _parsedData.Get(index, out DbRow row);

            CheckExpectedType(JsonTokenType.StartObject, row.TokenType);

            if (row.NumberOfRows == 0)
            {
                value = default;
                return false;
            }

            int endIndex = checked(row.NumberOfRows * DbRow.Size + index);

            return TryGetNamedPropertyValue(
                index + DbRow.Size,
                endIndex,
                propertyName,
                out value);
        }

        private bool TryGetNamedPropertyValue(
            int startIndex,
            int endIndex,
            ReadOnlySpan<byte> propertyName,
            out JsonElement value)
        {
            DbRow row;
            ReadOnlySpan<byte> documentSpan = _utf8Json.Span;

            int index = startIndex;

            while (index < endIndex)
            {
                _parsedData.Get(index, out row);
                Debug.Assert(row.TokenType == JsonTokenType.PropertyName);

                ReadOnlySpan<byte> currentPropertyName = documentSpan.Slice(row.Location, row.SizeOrLength);

                // If the property name is a match, the answer is the next element.
                if (currentPropertyName.SequenceEqual(propertyName))
                {
                    value = new JsonElement(this, index + DbRow.Size);
                    return true;
                }

                // Move to the value
                index += DbRow.Size;
                _parsedData.Get(index, out row);

                // Move past the value
                if (row.IsSimpleValue)
                {
                    index += DbRow.Size;
                }
                else
                {
                    index += DbRow.Size * (row.NumberOfRows + 1);
                }
            }

            value = default;
            return false;
        }
    }
}
