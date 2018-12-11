// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

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
                isFinalBlock: true,
                new JsonReaderState(maxDepth: int.MaxValue, readerOptions));

            var database = new CustomDb(DbRow.Size + utf8Json.Length);
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

            return new JsonDocument(utf8Json, database);
        }

        internal JsonTokenType GetJsonTokenType(int index)
        {
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            return _parsedData.GetJsonTokenType(index);
        }

        internal int GetArrayLength(int index)
        {
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            _parsedData.Get(index, out DbRow row);

            if (row.TokenType != JsonTokenType.StartArray)
            {
                throw new InvalidOperationException();
            }

            return row.SizeOrLength;
        }

        internal JsonElement GetArrayIndexElement(int currentIndex, int arrayIndex)
        {
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            _parsedData.Get(currentIndex, out DbRow row);

            if (row.TokenType != JsonTokenType.StartArray)
            {
                throw new InvalidOperationException();
            }

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
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

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
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

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
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            _parsedData.Get(index, out DbRow row);

            JsonTokenType type = row.TokenType;

            if (expectedType != type)
            {
                throw new InvalidOperationException();
            }

            ReadOnlySpan<byte> data = _utf8Json.Span;
            ReadOnlySpan<byte> segment = data.Slice(row.Location, row.SizeOrLength);

            // TODO(#33292): Unescape this.
            return Utf8JsonReader.Utf8Encoding.GetString(segment);
        }

        internal bool TryGetValue(int index, out int value)
        {
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            _parsedData.Get(index, out DbRow row);

            if (row.TokenType != JsonTokenType.Number)
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

            if (row.TokenType != JsonTokenType.Number)
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

            if (row.TokenType != JsonTokenType.Number)
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

            if (row.TokenType != JsonTokenType.Number)
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
            ReadOnlyMemory<byte> segment = GetRawValue(index);
            return Utf8JsonReader.Utf8Encoding.GetString(segment.Span);
        }

        internal JsonElement GetPropertyValue(int index)
        {
            if (GetJsonTokenType(index) != JsonTokenType.PropertyName)
            {
                throw new InvalidOperationException();
            }

            return new JsonElement(this, index + DbRow.Size);
        }

        internal string PrettyPrintProperty(int index)
        {
            if (_utf8Json.IsEmpty)
                throw new ObjectDisposedException(nameof(JsonDocument));

            _parsedData.Get(index, out DbRow row);
            Debug.Assert(row.TokenType == JsonTokenType.PropertyName);

            // The Location for the property name is where the name starts,
            // the quote is one UTF-8 Code Unit (byte) before it
            int propertyQuoteStart = row.Location - 1;
            int valueEnd;

            int valueIndex = index + DbRow.Size;
            _parsedData.Get(valueIndex, out row);

            JsonTokenType valueType = row.TokenType;

            if (valueType == JsonTokenType.String)
            {
                // String start to string end plus the end quote
                // (the open quote is included in the gap between the property name and value)
                valueEnd = row.Location + row.SizeOrLength + 1;
            }
            else if (valueType == JsonTokenType.StartObject || valueType == JsonTokenType.StartArray)
            {
                int endIndex = GetEndIndex(valueIndex, includeEndElement: false);
                _parsedData.Get(endIndex, out row);
                Debug.Assert(row.SizeOrLength == 1);

                valueEnd = row.Location + row.SizeOrLength;
            }
            else
            {
                valueEnd = row.Location + row.SizeOrLength;
            }

            // TODO(#33292): Unescape this.
            return Utf8JsonReader.Utf8Encoding.GetString(
                _utf8Json.Span.Slice(propertyQuoteStart, valueEnd - propertyQuoteStart));
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
    }
}
