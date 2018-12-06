// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// ------------------------------------------------------------------------------
// Changes to this file must follow the http://aka.ms/api-review process.
// ------------------------------------------------------------------------------

namespace System.Text.Json
{
    public enum JsonCommentHandling : byte
    {
        Allow = (byte)1,
        Disallow = (byte)0,
        Skip = (byte)2,
    }
    public sealed partial class JsonDocument : System.IDisposable
    {
        internal JsonDocument() { }
        public System.Text.Json.JsonElement RootElement { get { throw null; } }
        public void Dispose() { }
        public static System.Text.Json.JsonDocument Parse(System.ReadOnlyMemory<byte> utf8Json, System.Text.Json.JsonReaderOptions readerOptions) { throw null; }
    }
    public partial struct JsonElement
    {
        private object _dummy;
        public System.Text.Json.JsonElement this[int index] { get { throw null; } }
        public System.Text.Json.JsonElement this[System.ReadOnlySpan<byte> utf8PropertyName] { get { throw null; } }
        public System.Text.Json.JsonElement this[System.ReadOnlySpan<char> propertyName] { get { throw null; } }
        public System.Text.Json.JsonElement this[string propertyName] { get { throw null; } }
        public System.Text.Json.JsonTokenType Type { get { throw null; } }
        public System.Text.Json.JsonElement.ChildEnumerator EnumerateChildren() { throw null; }
        public int GetArrayLength() { throw null; }
        public bool GetBoolean() { throw null; }
        public double GetDouble() { throw null; }
        public int GetInt32() { throw null; }
        public long GetInt64() { throw null; }
        public string GetString() { throw null; }
        [System.CLSCompliantAttribute(false)]
        public ulong GetUInt64() { throw null; }
        public override string ToString() { throw null; }
        public bool TryGetProperty(System.ReadOnlySpan<byte> utf8PropertyName, out System.Text.Json.JsonElement value) { throw null; }
        public bool TryGetProperty(System.ReadOnlySpan<char> propertyName, out System.Text.Json.JsonElement value) { throw null; }
        public bool TryGetProperty(string propertyName, out System.Text.Json.JsonElement value) { throw null; }
        public bool TryGetRawData<T>(out System.ReadOnlyMemory<T> rawData) where T : struct { throw null; }
        public bool TryGetValue(out double value) { throw null; }
        public bool TryGetValue(out int value) { throw null; }
        public bool TryGetValue(out long value) { throw null; }
        [System.CLSCompliantAttribute(false)]
        public bool TryGetValue(out ulong value) { throw null; }
        public partial struct ChildEnumerator
        {
            private object _dummy;
            public System.Text.Json.JsonElement Current { get { throw null; } }
            public System.Text.Json.JsonElement.ChildEnumerator GetEnumerator() { throw null; }
            public bool MoveNext() { throw null; }
        }
    }
    public sealed partial class JsonReaderException : System.Exception
    {
        public JsonReaderException(string message, long lineNumber, long bytePositionInLine) { }
        public long BytePositionInLine { get { throw null; } }
        public long LineNumber { get { throw null; } }
        public override void GetObjectData(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context) { }
    }
    public partial struct JsonReaderOptions
    {
        private object _dummy;
        public System.Text.Json.JsonCommentHandling CommentHandling { get { throw null; } set { } }
    }
    public partial struct JsonReaderState
    {
        private object _dummy;
        public JsonReaderState(int maxDepth = 64, System.Text.Json.JsonReaderOptions options = default(System.Text.Json.JsonReaderOptions)) { throw null; }
        public long BytesConsumed { get { throw null; } }
        public int MaxDepth { get { throw null; } }
        public System.Text.Json.JsonReaderOptions Options { get { throw null; } }
        public System.SequencePosition Position { get { throw null; } }
    }
    public enum JsonTokenType : byte
    {
        Comment = (byte)11,
        EndArray = (byte)4,
        EndObject = (byte)2,
        False = (byte)9,
        None = (byte)0,
        Null = (byte)10,
        Number = (byte)7,
        PropertyName = (byte)5,
        StartArray = (byte)3,
        StartObject = (byte)1,
        String = (byte)6,
        True = (byte)8,
    }
    public ref partial struct Utf8JsonReader
    {
        private object _dummy;
        public Utf8JsonReader(in System.Buffers.ReadOnlySequence<byte> jsonData, bool isFinalBlock, System.Text.Json.JsonReaderState state) { throw null; }
        public Utf8JsonReader(System.ReadOnlySpan<byte> jsonData, bool isFinalBlock, System.Text.Json.JsonReaderState state) { throw null; }
        public long BytesConsumed { get { throw null; } }
        public int CurrentDepth { get { throw null; } }
        public System.Text.Json.JsonReaderState CurrentState { get { throw null; } }
        public bool HasValueSequence { get { throw null; } }
        public System.SequencePosition Position { get { throw null; } }
        public System.Text.Json.JsonTokenType TokenType { get { throw null; } }
        public System.Buffers.ReadOnlySequence<byte> ValueSequence { get { throw null; } }
        public System.ReadOnlySpan<byte> ValueSpan { get { throw null; } }
        public bool GetBooleanValue() { throw null; }
        public string GetStringValue() { throw null; }
        public bool Read() { throw null; }
        public bool TryGetDecimalValue(out decimal value) { throw null; }
        public bool TryGetDoubleValue(out double value) { throw null; }
        public bool TryGetInt32Value(out int value) { throw null; }
        public bool TryGetInt64Value(out long value) { throw null; }
        public bool TryGetSingleValue(out float value) { throw null; }
    }
}
