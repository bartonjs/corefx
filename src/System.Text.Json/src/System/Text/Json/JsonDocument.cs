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

        public JsonElement RootElement => new JsonElement(this, 0);

        private JsonDocument(ReadOnlyMemory<byte> utf8Json, CustomDb parsedData)
        {
            _utf8Json = utf8Json;
            _parsedData = parsedData;
        }

        public void Dispose()
        {
            if (_utf8Json.IsEmpty)
            {
                return;
            }

            _utf8Json = ReadOnlyMemory<byte>.Empty;
            _parsedData.Dispose();
        }

        public static JsonDocument Parse(ReadOnlyMemory<byte> utf8Json, JsonReaderOptions readerOptions)
        {
            ReadOnlySpan<byte> utf8JsonSpan = utf8Json.Span;
            Utf8JsonReader reader = new Utf8JsonReader(
                utf8JsonSpan,
                true,
                new JsonReaderState(maxDepth: int.MaxValue, readerOptions));

            var database = new CustomDb(ArrayPool<byte>.Shared, DbRow.Size + utf8Json.Length);
            var stack = new CustomStack(JsonReaderState.DefaultMaxDepth * StackRow.Size);

            try
            {
                Parse(utf8JsonSpan, reader, ref database, ref stack);
            }
            catch (Exception)
            {
                database.Dispose();
                throw;
            }
            finally
            {
                stack.Dispose();
            }

            return new JsonDocument(utf8Json, database);
        }

        internal JsonTokenType GetJsonTokenType(int index)
        {
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            return _parsedData.GetJsonTokenType(index);
        }

        internal JsonElement GetArrayIndexElement(int currentIndex, int arrayIndex)
        {
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            _parsedData.Get(currentIndex, out DbRow row);

            if (row.JsonType != JsonType.StartArray)
            {
                throw new InvalidOperationException();
            }

            int arrayLength = row.SizeOrLength;

            if ((uint)arrayIndex >= (uint)arrayLength)
            {
                throw new IndexOutOfRangeException();
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

        internal int GetEndIndex(int index)
        {
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            DbRow row;
            _parsedData.Get(index, out row);

            if (row.IsSimpleValue)
            {
                return index + DbRow.Size;
            }

            return index + DbRow.Size * (row.NumberOfRows + 1);
        }

        internal bool TryGetRawData<T>(int index, out ReadOnlyMemory<T> rawData) where T : struct
        {
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            if (typeof(T) != typeof(byte))
            {
                rawData = default;
                return false;
            }

            _parsedData.Get(index, out DbRow row);

            if (row.IsSimpleValue)
            {
                rawData = (ReadOnlyMemory<T>)(object)_utf8Json.Slice(row.Location, row.SizeOrLength);
                return true;
            }

            throw new NotImplementedException();
        }

        internal string GetString(int index)
        {
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            _parsedData.Get(index, out DbRow row);

            JsonType type = row.JsonType;

            switch (type)
            {
                case JsonType.String:
                // PropertyName
                    break;
                default:
                    throw new InvalidOperationException();
            }

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

            // TODO(#33292): Unescape this.
            return Encoding.UTF8.GetString(segment);
        }

        internal bool TryGetValue(int index, out int value)
        {
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            _parsedData.Get(index, out DbRow row);

            if (row.JsonType != JsonType.Number)
            {
                throw new InvalidOperationException();
            }

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

        internal bool TryGetValue(int index, out long value)
        {
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            _parsedData.Get(index, out DbRow row);

            if (row.JsonType != JsonType.Number)
            {
                throw new InvalidOperationException();
            }

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
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            _parsedData.Get(index, out DbRow row);

            if (row.JsonType != JsonType.Number)
            {
                throw new InvalidOperationException();
            }

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
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            _parsedData.Get(index, out DbRow row);

            if (row.JsonType != JsonType.Number)
            {
                throw new InvalidOperationException();
            }

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

        internal string GetRawValueAsString(int index)
        {
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            _parsedData.Get(index, out DbRow row);

            if (row.IsSimpleValue)
            {
                ReadOnlySpan<byte> data = _utf8Json.Span;
                ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);
                return Encoding.UTF8.GetString(segment);
            }

            throw new NotImplementedException();
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
                        database.SetHasChildren(parentLocation);
                    }

                    parentLocation = database.Length;

                    if (inArray)
                    {
                        arrayItemsCount++;
                    }

                    numberOfRowsForValues++;
                    database.Append(JsonType.StartObject, tokenStart);
                    var row = new StackRow(numberOfRowsForMembers + 1);
                    stack.Push(row);
                    numberOfRowsForMembers = 0;
                }
                else if (tokenType == JsonTokenType.EndObject)
                {
                    parentLocation = -1;

                    int rowIndex = database.FindIndexOfFirstUnsetSizeOrLength(JsonType.StartObject);

                    database.SetLength(rowIndex, numberOfRowsForMembers);

                    if (numberOfRowsForMembers != 0)
                    {
                        database.SetNumberOfRows(rowIndex, numberOfRowsForMembers);
                    }

                    StackRow row = stack.Pop();
                    numberOfRowsForMembers += row.SizeOrLength;
                }
                else if (tokenType == JsonTokenType.StartArray)
                {
                    if (parentLocation != -1)
                    {
                        database.SetHasChildren(parentLocation);
                    }

                    parentLocation = database.Length;

                    if (inArray)
                    {
                        arrayItemsCount++;
                    }

                    numberOfRowsForMembers++;
                    database.Append(JsonType.StartArray, tokenStart);
                    var row = new StackRow(arrayItemsCount, numberOfRowsForValues + 1);
                    stack.Push(row);
                    arrayItemsCount = 0;
                    numberOfRowsForValues = 0;
                }
                else if (tokenType == JsonTokenType.EndArray)
                {
                    parentLocation = -1;

                    int rowIndex = database.FindIndexOfFirstUnsetSizeOrLength(JsonType.StartArray);

                    database.SetLength(rowIndex, arrayItemsCount);

                    if (numberOfRowsForValues != 0)
                    {
                        database.SetNumberOfRows(rowIndex, numberOfRowsForValues);
                    }

                    // TODO: Record EndArray.
                    StackRow row = stack.Pop();
                    arrayItemsCount = row.SizeOrLength;
                    numberOfRowsForValues += row.NumberOfRows;
                }
                else if (tokenType == JsonTokenType.PropertyName)
                {
                    numberOfRowsForValues++;
                    numberOfRowsForMembers++;
                    database.Append(JsonType.String, tokenStart, reader.ValueSpan.Length);

                    if (inArray)
                    {
                        arrayItemsCount++;
                    }
                }
                else
                {
                    Debug.Assert(tokenType >= JsonTokenType.String && tokenType <= JsonTokenType.Null);
                    numberOfRowsForValues++;
                    numberOfRowsForMembers++;
                    database.Append((JsonType)(tokenType - 4), tokenStart, reader.ValueSpan.Length);

                    if (inArray)
                    {
                        arrayItemsCount++;
                    }
                }

                inArray = reader.IsInArray;
            }

            database.TrimExcess();
        }
    }
}
