// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace System.Text.Json
{
    partial class JsonDocument
    {
        // The database for the parsed structure of a JSON document.
        //
        // Every token from the document gets a row, which has one of the following forms:
        //
        // Value types (String, Number, True, False, Null, PropertyName)
        // * First int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for token offset
        // * Second int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for the token length
        // * Third int
        //   * 4 bits JsonTokenType
        //   * 28 bits unassigned / always clear
        //
        // EndObject / EndArray
        // * First int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for token offset
        // * Second int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for the token length (always 1, effectively unassigned)
        // * Third int
        //   * 4 bits JsonTokenType
        //   * 28 bits unassigned / always clear
        //
        // StartObject
        // * First int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for token offset
        // * Second int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for the token length (always 1, effectively unassigned)
        // * Third int
        //   * 4 bits JsonTokenType
        //   * 28 bits for the number of rows until the next value (never 0)
        //
        // StartArray
        // * First int
        //   * Top bit is unassigned / always clear
        //   * 31 bits for token offset
        // * Second int
        //   * Top bit is set if the array contains other arrays or objects ("complex" types)
        //   * 31 bits for the number of elements in this array
        // * Third int
        //   * 4 bits JsonTokenType
        //   * 28 bits for the number of rows until the next value (never 0)
        private struct CustomDb : IDisposable
        {
            private const int SizeOrLengthOffset = 4;
            private const int NumberOfRowsOffset = 8;

            internal int Length;
            private byte[] _rentedBuffer;

            internal CustomDb(int initialSize)
            {
                _rentedBuffer = ArrayPool<byte>.Shared.Rent(initialSize);
                Length = 0;
            }

            public void Dispose()
            {
                if (_rentedBuffer == null)
                {
                    return;
                }

                ArrayPool<byte>.Shared.Return(_rentedBuffer);
                _rentedBuffer = null;
                Length = 0;
            }

            internal void TrimExcess()
            {
                if (Length <= _rentedBuffer.Length / 2)
                {
                    byte[] newRent = ArrayPool<byte>.Shared.Rent(Length);
                    byte[] returnBuf = newRent;

                    if (newRent.Length < _rentedBuffer.Length)
                    {
                        Buffer.BlockCopy(_rentedBuffer, 0, newRent, 0, Length);
                        returnBuf = _rentedBuffer;
                        _rentedBuffer = newRent;
                    }

                    ArrayPool<byte>.Shared.Return(returnBuf);
                }
            }

            internal void Append(JsonTokenType tokenType, int startLocation, int length)
            {
                // StartArray or StartObject should have length -1, otherwise the length should not be -1.
                Debug.Assert(
                    (tokenType == JsonTokenType.StartArray || tokenType == JsonTokenType.StartObject) ==
                    (length == DbRow.UnknownSize));

                if (Length >= _rentedBuffer.Length - DbRow.Size)
                {
                    Enlarge();
                }

                DbRow row = new DbRow(tokenType, startLocation, length);
                MemoryMarshal.Write(_rentedBuffer.AsSpan(Length), ref row);
                Length += DbRow.Size;
            }

            private void Enlarge()
            {
                int size = _rentedBuffer.Length * 2;
                byte[] newArray = ArrayPool<byte>.Shared.Rent(size);
                Buffer.BlockCopy(_rentedBuffer, 0, newArray, 0, Length);
                ArrayPool<byte>.Shared.Return(_rentedBuffer);
                _rentedBuffer = newArray;
            }

            [Conditional("DEBUG")]
            private void AssertValidIndex(int index)
            {
                Debug.Assert(index >= 0);
                Debug.Assert(index <= Length - DbRow.Size, $"index {index} is out of bounds");
                Debug.Assert(index % DbRow.Size == 0, $"index {index} is not at a record start position");
            }

            internal void SetLength(int index, int length)
            {
                AssertValidIndex(index);
                Debug.Assert(length >= 0);
                Span<byte> destination = _rentedBuffer.AsSpan(index + 4);
                int cur = MemoryMarshal.Read<int>(destination);
                
                // Persist the most significant bit
                length |= (cur & unchecked((int)0x80000000));
                MemoryMarshal.Write(destination, ref length);
            }

            internal void SetNumberOfRows(int index, int numberOfRows)
            {
                AssertValidIndex(index);
                Debug.Assert(numberOfRows >= 1 && numberOfRows <= 0x0FFFFFFF);

                Span<byte> dataPos = _rentedBuffer.AsSpan(index + NumberOfRowsOffset);
                int current = MemoryMarshal.Read<int>(dataPos);

                // Persist the most significant nybble
                int value = (current & unchecked((int)0xF0000000)) | numberOfRows;
                MemoryMarshal.Write(dataPos, ref value);
            }

            internal void SetHasComplexChildren(int index)
            {
                AssertValidIndex(index);

                // The HasComplexChildren bit is the most significant bit of "SizeOrLength"
                Span<byte> dataPos = _rentedBuffer.AsSpan(index + SizeOrLengthOffset);
                int current = MemoryMarshal.Read<int>(dataPos);

                int value = current | unchecked((int)0x80000000);
                MemoryMarshal.Write(dataPos, ref value);
            }

            internal int FindIndexOfFirstUnsetSizeOrLength(JsonTokenType lookupType)
            {
                Debug.Assert(lookupType == JsonTokenType.StartObject || lookupType == JsonTokenType.StartArray);
                return FindOpenElement(lookupType);
            }

            private int FindOpenElement(JsonTokenType lookupType)
            {
                Span<byte> data = _rentedBuffer.AsSpan(0, Length);
               
                for (int i = Length - DbRow.Size; i >= 0; i -= DbRow.Size)
                {
                    DbRow row = MemoryMarshal.Read<DbRow>(data.Slice(i));

                    if (row.IsUnknownSize && row.TokenType == lookupType)
                    {
                        return i;
                    }
                }

                // We should never reach here.
                Debug.Fail($"Unable to find expected {lookupType} token");
                return -1;
            }

            internal void Get(int index, out DbRow row)
            {
                AssertValidIndex(index);
                row = MemoryMarshal.Read<DbRow>(_rentedBuffer.AsSpan(index));
            }

            internal JsonTokenType GetJsonTokenType(int index)
            {
                AssertValidIndex(index);
                uint union = MemoryMarshal.Read<uint>(_rentedBuffer.AsSpan(index + NumberOfRowsOffset));

                return (JsonTokenType)(union >> 28);
            }

#if DIAGNOSTIC
            internal string PrintDatabase()
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("Index  Offset  SizeOrLen  TokenType    Child IPV   NumRows");
                Span<byte> data = _rentedBuffer;

                for (int i = 0; i < Length; i += DbRow.Size)
                {
                    DbRow record = MemoryMarshal.Read<DbRow>(data.Slice(i));
                    sb.Append($"{i:D6} {record.Location:D7} {record.SizeOrLength:D10} ");
                    sb.Append(record.TokenType.ToString().PadRight(13));
                    sb.Append(record.HasChildren.ToString().PadRight(6));
                    sb.Append(record.IsPropertyValue.ToString().PadRight(6));
                    sb.AppendLine("" + record.NumberOfRows);
                }

                return sb.ToString();
            }
#endif
        }
    }
}
