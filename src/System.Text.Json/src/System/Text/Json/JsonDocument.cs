// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Internal.Runtime.CompilerServices;

namespace System.Text.Json
{
    public sealed partial class JsonDocument : IDisposable
    {
        private ReadOnlyMemory<byte> _utf8Json;
        private CustomDb _parsedData;
        private byte[] _extraRentedBytes;

        public JsonElement RootElement => new JsonElement(this, 0);

        private JsonDocument(ReadOnlyMemory<byte> utf8Json, CustomDb parsedData, byte[] extraRentedBytes)
        {
            Debug.Assert(!utf8Json.IsEmpty);

            _utf8Json = utf8Json;
            _parsedData = parsedData;
            _extraRentedBytes = extraRentedBytes;
        }

        public void Dispose()
        {
            if (_utf8Json.IsEmpty)
            {
                return;
            }

            int length = _utf8Json.Length;
            _utf8Json = ReadOnlyMemory<byte>.Empty;
            _parsedData.Dispose();

            if (_extraRentedBytes != null)
            {
                _extraRentedBytes.AsSpan(0, length).Clear();
                ArrayPool<byte>.Shared.Return(_extraRentedBytes);
                _extraRentedBytes = null;
            }
        }

        public static JsonDocument Parse(ReadOnlyMemory<byte> utf8Json, JsonReaderOptions readerOptions = default)
        {
            CheckSupportedOptions(readerOptions);

            return Parse(utf8Json, readerOptions, null);
        }

        public static JsonDocument Parse(ReadOnlySequence<byte> utf8Json, JsonReaderOptions readerOptions = default)
        {
            CheckSupportedOptions(readerOptions);

            if (utf8Json.IsSingleSegment)
            {
                return Parse(utf8Json.First, readerOptions, null);
            }

            int length = checked((int)utf8Json.Length);
            byte[] utf8Bytes = ArrayPool<byte>.Shared.Rent(length);

            try
            {
                utf8Bytes.CopyTo(utf8Bytes.AsSpan());
                return Parse(utf8Bytes.AsMemory(0, length), readerOptions, utf8Bytes);
            }
            catch
            {
                utf8Bytes.AsSpan(0, length).Clear();
                ArrayPool<byte>.Shared.Return(utf8Bytes);
                throw;
            }
        }

        public static JsonDocument Parse(ReadOnlyMemory<char> json, JsonReaderOptions readerOptions = default)
        {
            CheckSupportedOptions(readerOptions);

            ReadOnlySpan<char> jsonChars = json.Span;
            int byteCount = Utf8JsonReader.Utf8Encoding.GetByteCount(jsonChars);
            byte[] utf8Bytes = ArrayPool<byte>.Shared.Rent(byteCount);

            try
            {
                int byteCount2 = Utf8JsonReader.Utf8Encoding.GetBytes(jsonChars, utf8Bytes);
                Debug.Assert(byteCount == byteCount2);

                return Parse(utf8Bytes.AsMemory(0, byteCount2), readerOptions, utf8Bytes);
            }
            catch
            {
                utf8Bytes.AsSpan(0, byteCount).Clear();
                ArrayPool<byte>.Shared.Return(utf8Bytes);
                throw;
            }
        }

        public static JsonDocument Parse(string json, JsonReaderOptions readerOptions = default)
        {
            CheckSupportedOptions(readerOptions);

            return Parse(json.AsMemory(), readerOptions);
        }

        private static JsonDocument Parse(
            ReadOnlyMemory<byte> utf8Json,
            JsonReaderOptions readerOptions,
            byte[] extraRentedBytes)
        {
            ReadOnlySpan<byte> utf8JsonSpan = utf8Json.Span;
            Utf8JsonReader reader = new Utf8JsonReader(
                utf8JsonSpan,
                isFinalBlock: true,
                new JsonReaderState(JsonReaderState.DefaultMaxDepth, readerOptions));

            var database = new CustomDb(utf8Json.Length);
            var stack = new CustomStack(JsonReaderState.DefaultMaxDepth * StackRow.Size);

            try
            {
                Parse(utf8JsonSpan, reader, ref database, ref stack);
            }
            catch
            {
                database.Dispose();
                throw;
            }
            finally
            {
                stack.Dispose();
            }

            return new JsonDocument(utf8Json, database, extraRentedBytes);
        }

        internal JsonTokenType GetJsonTokenType(int index)
        {
            CheckNotDisposed();

            return _parsedData.GetJsonTokenType(index);
        }

        internal int GetArrayLength(int index)
        {
            CheckNotDisposed();

            _parsedData.Get(index, out DbRow row);

            CheckExpectedType(JsonTokenType.StartArray, row.TokenType);

            return row.SizeOrLength;
        }

        internal JsonElement GetArrayIndexElement(int currentIndex, int arrayIndex)
        {
            CheckNotDisposed();

            _parsedData.Get(currentIndex, out DbRow row);

            CheckExpectedType(JsonTokenType.StartArray, row.TokenType);

            int arrayLength = row.SizeOrLength;

            if ((uint)arrayIndex >= (uint)arrayLength)
            {
                throw new IndexOutOfRangeException();
            }

            if (!row.HasComplexChildren)
            {
                return new JsonElement(this, currentIndex + (arrayIndex * DbRow.Size));
            }

            int elementCount = 0;
            int objectOffset = currentIndex + DbRow.Size;

            for (; objectOffset < _parsedData.Length; objectOffset += DbRow.Size)
            {
                if (arrayIndex == elementCount)
                {
                    return new JsonElement(this, objectOffset);
                }

                _parsedData.Get(objectOffset, out row);

                if (!row.IsSimpleValue)
                {
                    objectOffset += DbRow.Size * row.NumberOfRows;
                }

                elementCount++;
            }

            Debug.Fail(
                $"Ran out of database searching for array index {arrayIndex} from {currentIndex} when length was {arrayLength}");
            throw new IndexOutOfRangeException();
        }

        internal int GetEndIndex(int index, bool includeEndElement)
        {
            CheckNotDisposed();

            DbRow row;
            _parsedData.Get(index, out row);

            if (row.IsSimpleValue)
            {
                return index + DbRow.Size;
            }

            int endIndex = index + DbRow.Size * row.NumberOfRows;

            if (includeEndElement)
            {
                endIndex += DbRow.Size;
            }

            return endIndex;
        }

        internal ReadOnlyMemory<byte> GetRawValue(int index)
        {
            CheckNotDisposed();

            _parsedData.Get(index, out DbRow row);

            if (row.IsSimpleValue)
            {
                return _utf8Json.Slice(row.Location, row.SizeOrLength);
            }

            int endElementIdx = GetEndIndex(index, includeEndElement: false);
            int start = row.Location;
            _parsedData.Get(endElementIdx, out row);
            return _utf8Json.Slice(start, row.Location - start + row.SizeOrLength);
        }

        internal string GetString(int index, JsonTokenType expectedType)
        {
            CheckNotDisposed();

            _parsedData.Get(index, out DbRow row);

            JsonTokenType tokenType = row.TokenType;

            if (tokenType == JsonTokenType.Null)
            {
                return null;
            }

            CheckExpectedType(expectedType, tokenType);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

            // TODO(#33292): Unescape this.
            return Utf8JsonReader.Utf8Encoding.GetString(segment);
        }

        internal string GetNameOfPropertyValue(int index)
        {
            // The property name is one row before the property value
            return GetString(index - DbRow.Size, JsonTokenType.PropertyName);
        }

        internal bool TryGetValue(int index, out int value)
        {
            CheckNotDisposed();

            _parsedData.Get(index, out DbRow row);

            CheckExpectedType(JsonTokenType.Number, row.TokenType);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

            if (Utf8Parser.TryParse(segment, out int tmp, out int consumed) &&
                consumed == segment.Length)
            {
                value = tmp;
                return true;
            }

            value = default;
            return false;
        }

        internal bool TryGetValue(int index, out uint value)
        {
            CheckNotDisposed();

            _parsedData.Get(index, out DbRow row);

            CheckExpectedType(JsonTokenType.Number, row.TokenType);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

            if (Utf8Parser.TryParse(segment, out uint tmp, out int consumed) &&
                consumed == segment.Length)
            {
                value = tmp;
                return true;
            }

            value = default;
            return false;
        }

        internal bool TryGetValue(int index, out long value)
        {
            CheckNotDisposed();

            _parsedData.Get(index, out DbRow row);

            CheckExpectedType(JsonTokenType.Number, row.TokenType);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

            if (Utf8Parser.TryParse(segment, out long tmp, out int consumed) &&
                consumed == segment.Length)
            {
                value = tmp;
                return true;
            }

            value = default;
            return false;
        }

        internal bool TryGetValue(int index, out ulong value)
        {
            CheckNotDisposed();

            _parsedData.Get(index, out DbRow row);

            CheckExpectedType(JsonTokenType.Number, row.TokenType);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

            if (Utf8Parser.TryParse(segment, out ulong tmp, out int consumed) &&
                consumed == segment.Length)
            {
                value = tmp;
                return true;
            }

            value = default;
            return false;
        }

        internal bool TryGetValue(int index, out double value)
        {
            CheckNotDisposed();

            _parsedData.Get(index, out DbRow row);

            CheckExpectedType(JsonTokenType.Number, row.TokenType);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

            if (Utf8JsonReader.TryGetDoubleValue(segment, out double tmp))
            {
                value = tmp;
                return true;
            }

            value = default;
            return false;
        }

        internal bool TryGetValue(int index, out float value)
        {
            CheckNotDisposed();

            _parsedData.Get(index, out DbRow row);

            CheckExpectedType(JsonTokenType.Number, row.TokenType);

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

            if (Utf8JsonReader.TryGetSingleValue(segment, out float tmp))
            {
                value = tmp;
                return true;
            }

            value = default;
            return false;
        }

        internal string GetRawValueAsString(int index)
        {
            ReadOnlyMemory<byte> segment = GetRawValue(index);
            return Utf8JsonReader.Utf8Encoding.GetString(segment.Span);
        }

        private static void Parse(
            ReadOnlySpan<byte> utf8JsonSpan,
            Utf8JsonReader reader,
            ref CustomDb database,
            ref CustomStack stack)
        {
            bool inArray = false;
            int arrayItemsCount = 0;
            int numberOfRowsForMembers = 0;
            int numberOfRowsForValues = 0;
            int parentLocation = -1;

            ref byte jsonStart = ref MemoryMarshal.GetReference(utf8JsonSpan);

            while (reader.Read())
            {
                JsonTokenType tokenType = reader.TokenType;

                int tokenStart = Unsafe.ByteOffset(
                    ref jsonStart,
                    ref MemoryMarshal.GetReference(reader.ValueSpan)).ToInt32();

                if (tokenType == JsonTokenType.StartObject)
                {
                    if (parentLocation != -1)
                    {
                        database.SetHasComplexChildren(parentLocation);
                    }

                    parentLocation = database.Length;

                    if (inArray)
                    {
                        arrayItemsCount++;
                    }

                    numberOfRowsForValues++;
                    database.Append(tokenType, tokenStart, DbRow.UnknownSize);
                    var row = new StackRow(numberOfRowsForMembers + 1);
                    stack.Push(row);
                    numberOfRowsForMembers = 0;
                }
                else if (tokenType == JsonTokenType.EndObject)
                {
                    parentLocation = -1;

                    int rowIndex = database.FindIndexOfFirstUnsetSizeOrLength(JsonTokenType.StartObject);

                    numberOfRowsForValues++;
                    numberOfRowsForMembers++;
                    database.SetLength(rowIndex, numberOfRowsForMembers);

                    database.Append(tokenType, tokenStart, reader.ValueSpan.Length);
                    database.SetNumberOfRows(rowIndex, numberOfRowsForMembers);

                    StackRow row = stack.Pop();
                    numberOfRowsForMembers += row.SizeOrLength;
                }
                else if (tokenType == JsonTokenType.StartArray)
                {
                    if (parentLocation != -1)
                    {
                        database.SetHasComplexChildren(parentLocation);
                    }

                    parentLocation = database.Length;

                    if (inArray)
                    {
                        arrayItemsCount++;
                    }

                    numberOfRowsForMembers++;
                    database.Append(tokenType, tokenStart, DbRow.UnknownSize);
                    var row = new StackRow(arrayItemsCount, numberOfRowsForValues + 1);
                    stack.Push(row);
                    arrayItemsCount = 0;
                    numberOfRowsForValues = 0;
                }
                else if (tokenType == JsonTokenType.EndArray)
                {
                    parentLocation = -1;

                    int rowIndex = database.FindIndexOfFirstUnsetSizeOrLength(JsonTokenType.StartArray);

                    numberOfRowsForValues++;
                    numberOfRowsForMembers++;
                    database.SetLength(rowIndex, arrayItemsCount);
                    database.SetNumberOfRows(rowIndex, numberOfRowsForValues);

                    database.Append(tokenType, tokenStart, reader.ValueSpan.Length);
                    StackRow row = stack.Pop();
                    arrayItemsCount = row.SizeOrLength;
                    numberOfRowsForValues += row.NumberOfRows;
                }
                else if (tokenType == JsonTokenType.PropertyName)
                {
                    numberOfRowsForValues++;
                    numberOfRowsForMembers++;
                    database.Append(tokenType, tokenStart, reader.ValueSpan.Length);

                    Debug.Assert(!inArray);
                }
                else
                {
                    Debug.Assert(tokenType >= JsonTokenType.String && tokenType <= JsonTokenType.Null);
                    numberOfRowsForValues++;
                    numberOfRowsForMembers++;
                    database.Append(tokenType, tokenStart, reader.ValueSpan.Length);

                    if (inArray)
                    {
                        arrayItemsCount++;
                    }
                }

                inArray = reader.IsInArray;
            }

            database.TrimExcess();
        }

        private void CheckNotDisposed()
        {
            if (_utf8Json.IsEmpty)
            {
                throw new ObjectDisposedException(nameof(JsonDocument));
            }
        }

        private void CheckExpectedType(JsonTokenType expected, JsonTokenType actual)
        {
            if (expected != actual)
            {
                throw new InvalidOperationException();
            }
        }

        private static void CheckSupportedOptions(JsonReaderOptions readerOptions)
        {
            if (readerOptions.CommentHandling == JsonCommentHandling.Allow)
            {
                throw new ArgumentException(
                    "Comments cannot be incorporated into JsonDocument, only comment handling modes Skip and Allow are supported.",
                    nameof(readerOptions));
            }
        }
    }
}
