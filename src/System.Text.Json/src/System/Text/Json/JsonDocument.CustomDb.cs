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
        private struct CustomDb : IDisposable
        {
            private const int NumberOfRowsOffset = 8;

            internal int Length;
            private byte[] _rentedBuffer;
            private ArrayPool<byte> _pool;

            internal CustomDb(ArrayPool<byte> pool, int initialSize)
            {
                _pool = pool;
                _rentedBuffer = _pool.Rent(initialSize);
                Length = 0;
            }

            public void Dispose()
            {
                if (_rentedBuffer == null)
                {
                    return;
                }

                _pool.Return(_rentedBuffer);
                _rentedBuffer = null;
                _pool = null;
                Length = 0;
            }

            internal void TrimExcess()
            {
                if (Length <= _rentedBuffer.Length / 2)
                {
                    byte[] newRent = _pool.Rent(Length);
                    byte[] returnBuf = newRent;

                    if (newRent.Length < _rentedBuffer.Length)
                    {
                        Buffer.BlockCopy(_rentedBuffer, 0, newRent, 0, Length);
                        returnBuf = _rentedBuffer;
                        _rentedBuffer = newRent;
                    }

                    _pool.Return(returnBuf);
                }
            }

            internal void Append(JsonType jsonType, int startLocation, int LengthOrNumberOfRows = DbRow.UnknownSize)
            {
                Debug.Assert(jsonType >= JsonType.StartObject && jsonType <= JsonType.Null);
                Debug.Assert(startLocation >= 0);
                Debug.Assert(LengthOrNumberOfRows >= DbRow.UnknownSize);

                if (Length >= _rentedBuffer.Length - DbRow.Size)
                {
                    Enlarge();
                }

                var dbRow = new DbRow(jsonType, startLocation, LengthOrNumberOfRows);
                MemoryMarshal.Write(_rentedBuffer.AsSpan(Length), ref dbRow);
                Length += DbRow.Size;
            }

            private void Enlarge()
            {
                int size = _rentedBuffer.Length * 2;
                byte[] newArray = _pool.Rent(size);
                Buffer.BlockCopy(_rentedBuffer, 0, newArray, 0, Length);
                _pool.Return(_rentedBuffer);
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
                MemoryMarshal.Write(_rentedBuffer.AsSpan(index + 4), ref length);
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

            internal void SetHasChildren(int index)
            {
                AssertValidIndex(index);

                // The HasChildren bit is the most significant bit of "NumberOfRows"
                Span<byte> dataPos = _rentedBuffer.AsSpan(index + NumberOfRowsOffset);
                int current = MemoryMarshal.Read<int>(dataPos);

                int value = current | unchecked((int)0x80000000);
                MemoryMarshal.Write(dataPos, ref value);
            }

            internal int FindIndexOfFirstUnsetSizeOrLength(JsonType lookupType)
            {
                Debug.Assert(lookupType == JsonType.StartObject || lookupType == JsonType.StartArray);
                return BackwardPass(lookupType);
            }

            private int ForwardPass(JsonType lookupType)
            {
                Span<byte> data = _rentedBuffer.AsSpan(0, Length);

                for (int i = 0; i < Length; i += DbRow.Size)
                {
                    DbRow row = MemoryMarshal.Read<DbRow>(data.Slice(i));

                    if (row.SizeOrLength == DbRow.UnknownSize && row.JsonType == lookupType)
                    {
                        return i;
                    }

                    if (!row.IsSimpleValue)
                    {
                        i += row.NumberOfRows * DbRow.Size;
                    }
                }

                // We should never reach here.
                Debug.Assert(false);
                return -1;
            }

            private int BackwardPass(JsonType lookupType)
            {
                Span<byte> data = _rentedBuffer.AsSpan(0, Length);
               
                for (int i = Length - DbRow.Size; i >= 0; i -= DbRow.Size)
                {
                    DbRow row = MemoryMarshal.Read<DbRow>(data.Slice(i));
                    if (row.SizeOrLength == DbRow.UnknownSize && row.JsonType == lookupType)
                    {
                        return i;
                    }
                }

                // We should never reach here.
                Debug.Assert(false);
                return -1;
            }

            internal DbRow Get() => MemoryMarshal.Read<DbRow>(_rentedBuffer.AsSpan());

            internal DbRow Get(int index)
            {
                AssertValidIndex(index);
                return MemoryMarshal.Read<DbRow>(_rentedBuffer.AsSpan(index));
            }

            internal void Get(int index, out DbRow row)
            {
                AssertValidIndex(index);
                row = MemoryMarshal.Read<DbRow>(_rentedBuffer.AsSpan(index));
            }

            internal int GetLocation() => MemoryMarshal.Read<int>(_rentedBuffer.AsSpan());

            internal int GetLocation(int index)
            {
                AssertValidIndex(index);
                return MemoryMarshal.Read<int>(_rentedBuffer.AsSpan());
            }

            internal int GetSizeOrLength(int index)
            {
                AssertValidIndex(index);
                return MemoryMarshal.Read<int>(_rentedBuffer.AsSpan(index + 4));
            }

            internal JsonTokenType GetJsonTokenType(int index = 0)
            {
                AssertValidIndex(index);
                int union = MemoryMarshal.Read<int>(_rentedBuffer.AsSpan(index + NumberOfRowsOffset));
                JsonType jsonType = (JsonType)((union & 0x70000000) >> 28);

                JsonTokenType tokenType = (JsonTokenType)(jsonType + 4);
                if (jsonType == JsonType.StartObject)
                {
                    tokenType = JsonTokenType.StartObject;
                }
                else if (jsonType == JsonType.StartArray)
                {
                    tokenType = JsonTokenType.StartArray;
                }

                return tokenType;
            }

            internal bool GetHasChildren(int index = 0)
            {
                AssertValidIndex(index);
                int union = MemoryMarshal.Read<int>(_rentedBuffer.AsSpan(index + NumberOfRowsOffset));
                return union < 0;
            }

            internal int GetNumberOfRows(int index = 0)
            {
                AssertValidIndex(index);
                int union = MemoryMarshal.Read<int>(_rentedBuffer.AsSpan(index + NumberOfRowsOffset));
                return union & 0x0FFFFFFF;
            }

            internal string PrintDatabase()
            {
                StringBuilder sb = new StringBuilder();
                sb.Append(nameof(DbRow.Location) + "\t" + nameof(DbRow.SizeOrLength) + "\t" + nameof(DbRow.JsonType) +
                          "\t" + nameof(DbRow.HasChildren) + "\t" + nameof(DbRow.NumberOfRows) + "\r\n");

                Span<byte> data = _rentedBuffer;

                for (int i = 0; i < Length; i += DbRow.Size)
                {
                    DbRow record = MemoryMarshal.Read<DbRow>(data.Slice(i));
                    sb.Append(record.Location + "\t" + record.SizeOrLength + "\t" + record.JsonType + "\t" +
                              record.HasChildren + "\t" + record.NumberOfRows + "\r\n");
                }

                return sb.ToString();
            }
        }
    }
}
