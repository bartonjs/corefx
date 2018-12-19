// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using Microsoft.Xunit.Performance;
using Newtonsoft.Json.Linq;
using Xunit;

namespace System.Text.Json.Performance.Tests
{
    public class Perf_JsonDocument
    {
        private const int InnerIterCount = 300;

        [Benchmark(InnerIterationCount = InnerIterCount)]
        [InlineData(-2)]
        [InlineData(-1)]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(21)]
        [InlineData(2136)]
        public void ReadBasicJsonWithLargeNum(int repeatCount)
        {
            ParseOnly(BasicJsonWithLargeNum, repeatCount);
        }

        [Benchmark(InnerIterationCount = InnerIterCount)]
        [InlineData(1, 0)]
        [InlineData(2, 0)]
        [InlineData(2, 1)]
        [InlineData(21, 0)]
        [InlineData(21, 10)]
        [InlineData(21, 20)]
        [InlineData(2136, 0)]
        [InlineData(2136, 20)]
        [InlineData(2136, 1068)]
        [InlineData(2136, 2000)]
        [InlineData(2136, 2135)]
        public void IndexBasicJsonWithLargeNum(int repeatCount, int index)
        {
            Evaluate(
                BasicJsonWithLargeNum,
                repeatCount,
                doc => { doc.RootElement[index].GetProperty("phoneNumbers")[1].ToString(); });
        }

        [Benchmark(InnerIterationCount = InnerIterCount)]
        [InlineData(-2)]
        [InlineData(-1)]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(21)]
        [InlineData(2136)]
        public void ReadBasicJsonWithLargeNum_JsonNet(int repeatCount)
        {
            ParseOnlyJsonNet(BasicJsonWithLargeNum, repeatCount);
        }

        [Benchmark(InnerIterationCount = InnerIterCount)]
        [InlineData(1, 0)]
        [InlineData(2, 0)]
        [InlineData(2, 1)]
        [InlineData(21, 0)]
        [InlineData(21, 10)]
        [InlineData(21, 20)]
        [InlineData(2136, 0)]
        [InlineData(2136, 20)]
        [InlineData(2136, 1068)]
        [InlineData(2136, 2000)]
        [InlineData(2136, 2135)]
        public void IndexBasicJsonWithLargeNum_JsonNet(int repeatCount, int index)
        {
            EvaluateJsonNet(
                BasicJsonWithLargeNum,
                repeatCount,
                token => { token[index]["phoneNumbers"][1].ToString(); });
        }

        [Benchmark(InnerIterationCount = InnerIterCount)]
        [InlineData(-2)]
        [InlineData(-1)]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(21)]
        [InlineData(2136)]
        public void BasicJasonWithLargeNumTouchEveryElement(int repeatCount)
        {
            int len = Prepare(BasicJsonWithLargeNum, repeatCount, out byte[] rented);
            ReadOnlyMemory<byte> buf = rented.AsMemory(0, len);

            foreach (var iteration in Benchmark.Iterations)
            {
                using (iteration.StartMeasurement())
                {
                    for (int i = 0; i < Benchmark.InnerIterationCount; i++)
                    {
                        using (JsonDocument doc = JsonDocument.Parse(buf, default))
                        {
                            TouchEverything(doc.RootElement);
                        }
                    }
                }
            }
        }

        [Benchmark(InnerIterationCount = InnerIterCount)]
        [InlineData(-2)]
        [InlineData(-1)]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(21)]
        [InlineData(2136)]
        public void BasicJasonWithLargeNumTouchEveryElement_JsonNet(int repeatCount)
        {
            int len = Prepare(BasicJsonWithLargeNum, repeatCount, out byte[] rented);
            ReadOnlyMemory<byte> buf = rented.AsMemory(0, len);
            string str = Encoding.UTF8.GetString(buf.Span);

            foreach (var iteration in Benchmark.Iterations)
            {
                using (iteration.StartMeasurement())
                {
                    for (int i = 0; i < Benchmark.InnerIterationCount; i++)
                    {
                        JToken token = JToken.Parse(str);
                        TouchEverything(token);
                    }
                }
            }
        }

        private static void TouchEverything(JsonElement element)
        {
            // Reading the type touched it.
            switch (element.Type)
            {
                case JsonValueType.Array:
                {
                    foreach (JsonElement child in element.EnumerateArray())
                    {
                        TouchEverything(child);
                    }

                    break;
                }
                case JsonValueType.Object:
                {
                    foreach (JsonProperty child in element.EnumerateObject())
                    {
                        TouchEverything(child.Value);
                    }

                    break;
                }
            }
        }

        private static void TouchEverything(JToken token)
        {
            object val;

            switch (token.Type)
            {
                case JTokenType.Array:
                case JTokenType.Object:
                {
                    foreach (JToken child in token.Children())
                    {
                        TouchEverything(child);
                    }

                    break;
                }
                case JTokenType.Property:
                    JProperty prop = (JProperty)token;
                    val = prop.Name;
                    TouchEverything(prop.Value);
                    break;
                default:
                    val = ((JValue)token).Value;
                    break;
            }
        }

        private static void ParseOnly(string seed, int repeatCount)
        {
            int len = Prepare(seed, repeatCount, out byte[] rented);
            ReadOnlyMemory<byte> buf = rented.AsMemory(0, len);

            foreach (var iteration in Benchmark.Iterations)
            {
                using (iteration.StartMeasurement())
                {
                    for (int i = 0; i < Benchmark.InnerIterationCount; i++)
                    {
                        using (JsonDocument doc = JsonDocument.Parse(buf, default))
                        {
                        }
                    }
                }
            }

            ArrayPool<byte>.Shared.Return(rented);
        }

        private static void ParseOnlyJsonNet(string seed, int repeatCount)
        {
            int len = Prepare(seed, repeatCount, out byte[] rented);
            ReadOnlySpan<byte> buf = rented.AsSpan(0, len);
            string str = Encoding.UTF8.GetString(buf);

            foreach (var iteration in Benchmark.Iterations)
            {
                using (iteration.StartMeasurement())
                {
                    for (int i = 0; i < Benchmark.InnerIterationCount; i++)
                    {
                        JToken token = JToken.Parse(str);
                    }
                }
            }

            ArrayPool<byte>.Shared.Return(rented);
        }

        private static void Evaluate(string seed, int repeatCount, Action<JsonDocument> action)
        {
            int len = Prepare(seed, repeatCount, out byte[] rented);
            ReadOnlyMemory<byte> buf = rented.AsMemory(0, len);

            foreach (var iteration in Benchmark.Iterations)
            {
                using (iteration.StartMeasurement())
                {
                    for (int i = 0; i < Benchmark.InnerIterationCount; i++)
                    {
                        using (JsonDocument doc = JsonDocument.Parse(buf, default))
                        {
                            action(doc);
                        }
                    }
                }
            }

            ArrayPool<byte>.Shared.Return(rented);
        }

        private static void EvaluateJsonNet(string seed, int repeatCount, Action<JToken> action)
        {
            int len = Prepare(seed, repeatCount, out byte[] rented);
            ReadOnlySpan<byte> buf = rented.AsSpan(0, len);
            string str = Encoding.UTF8.GetString(buf);

            foreach (var iteration in Benchmark.Iterations)
            {
                using (iteration.StartMeasurement())
                {
                    for (int i = 0; i < Benchmark.InnerIterationCount; i++)
                    {
                        JToken token = JToken.Parse(str);
                        action(token);
                    }
                }
            }

            ArrayPool<byte>.Shared.Return(rented);
        }

        private static int Prepare(string seed, int repeatCount, out byte[] rented)
        {
            int seedSize = Encoding.UTF8.GetByteCount(seed);

            if (repeatCount < 0)
            {
                rented = ArrayPool<byte>.Shared.Rent(seedSize);
                return Encoding.UTF8.GetBytes(seed, rented);
            }

            // There won't be a comma after the last one, so this is off by one, except when repeat is 0.
            // But that's okay.
            int totalSize = (seedSize + 1) * repeatCount + 2;
            rented = ArrayPool<byte>.Shared.Rent(totalSize);
            Span<byte> span = rented;
            span[0] = (byte)'[';
            Span<byte> utf8Seed = default;
            int closePos = 1;

            if (repeatCount > 0)
            {
                int len = Encoding.UTF8.GetBytes(seed, span.Slice(1));
                span[1 + len] = (byte)',';

                utf8Seed = span.Slice(1, len + 1);
                int writeOffset = len + 2;

                for (int i = 1; i < repeatCount; i++)
                {
                    utf8Seed.CopyTo(span.Slice(writeOffset));
                    writeOffset += utf8Seed.Length;
                }

                // Overwrite the last comma
                closePos = writeOffset - 1;
            }

            span[closePos] = (byte)']';
            return closePos + 1;
        }

        private const string BasicJsonWithLargeNum =
            "{\"age\":30,\"first\":\"John\",\"last\":\"Smith\",\"phoneNumbers\":[\"425-000-1212\",\"425-000-1213\"],\"address\":{\"street\":\"1MicrosoftWay\",\"city\":\"Redmond\",\"zip\":98052},\"IDs\":[425,-70,9223372036854775807]}";
    }
}
