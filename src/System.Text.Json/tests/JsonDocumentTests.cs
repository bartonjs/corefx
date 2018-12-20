// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Collections;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace System.Text.Json.Tests
{
    public static class JsonDocumentTests
    {
        public static IEnumerable<object[]> TestCases
        {
            get
            {
                return new List<object[]>
                {
                    new object[] { true, Tests.TestCaseType.Basic, SR.BasicJson},
                    new object[] { true, Tests.TestCaseType.BasicLargeNum, SR.BasicJsonWithLargeNum}, // Json.NET treats numbers starting with 0 as octal (0425 becomes 277)
                    new object[] { true, Tests.TestCaseType.BroadTree, SR.BroadTree}, // \r\n behavior is different between Json.NET and System.Text.Json
                    new object[] { true, Tests.TestCaseType.DeepTree, SR.DeepTree},
                    new object[] { true, Tests.TestCaseType.FullSchema1, SR.FullJsonSchema1},
                    new object[] { true, Tests.TestCaseType.HelloWorld, SR.HelloWorld},
                    new object[] { true, Tests.TestCaseType.LotsOfNumbers, SR.LotsOfNumbers},
                    new object[] { true, Tests.TestCaseType.LotsOfStrings, SR.LotsOfStrings},
                    new object[] { true, Tests.TestCaseType.ProjectLockJson, SR.ProjectLockJson},
                    new object[] { true, Tests.TestCaseType.Json400B, SR.Json400B},
                    new object[] { true, Tests.TestCaseType.Json4KB, SR.Json4KB},
                    new object[] { true, Tests.TestCaseType.Json40KB, SR.Json40KB},
                    new object[] { true, Tests.TestCaseType.Json400KB, SR.Json400KB},

                    new object[] { false, Tests.TestCaseType.Basic, SR.BasicJson},
                    new object[] { false, Tests.TestCaseType.BasicLargeNum, SR.BasicJsonWithLargeNum}, // Json.NET treats numbers starting with 0 as octal (0425 becomes 277)
                    new object[] { false, Tests.TestCaseType.BroadTree, SR.BroadTree}, // \r\n behavior is different between Json.NET and System.Text.Json
                    new object[] { false, Tests.TestCaseType.DeepTree, SR.DeepTree},
                    new object[] { false, Tests.TestCaseType.FullSchema1, SR.FullJsonSchema1},
                    new object[] { false, Tests.TestCaseType.HelloWorld, SR.HelloWorld},
                    new object[] { false, Tests.TestCaseType.LotsOfNumbers, SR.LotsOfNumbers},
                    new object[] { false, Tests.TestCaseType.LotsOfStrings, SR.LotsOfStrings},
                    new object[] { false, Tests.TestCaseType.ProjectLockJson, SR.ProjectLockJson},
                    new object[] { false, Tests.TestCaseType.Json400B, SR.Json400B},
                    new object[] { false, Tests.TestCaseType.Json4KB, SR.Json4KB},
                    new object[] { false, Tests.TestCaseType.Json40KB, SR.Json40KB},
                    new object[] { false, Tests.TestCaseType.Json400KB, SR.Json400KB},
                };
            }
        }

        // TestCaseType is only used to give the json strings a descriptive name within the unit tests.
        public enum TestCaseType
        {
            HelloWorld,
            Basic,
            BasicLargeNum,
            SpecialNumForm,
            SpecialStrings,
            ProjectLockJson,
            FullSchema1,
            FullSchema2,
            DeepTree,
            BroadTree,
            LotsOfNumbers,
            LotsOfStrings,
            Json400B,
            Json4KB,
            Json40KB,
            Json400KB,
        }

        private static string ReadHelloWorld(JToken obj)
        {
            string message = (string)obj["message"];
            return message;
        }

        private static string ReadJson400KB(JToken obj)
        {
            var sb = new StringBuilder();
            foreach (JToken token in obj)
            {
                sb.Append((string)token["_id"]);
                sb.Append((int)token["index"]);
                sb.Append((string)token["guid"]);
                sb.Append((bool)token["isActive"]);
                sb.Append((string)token["balance"]);
                sb.Append((string)token["picture"]);
                sb.Append((int)token["age"]);
                sb.Append((string)token["eyeColor"]);
                sb.Append((string)token["name"]);
                sb.Append((string)token["gender"]);
                sb.Append((string)token["company"]);
                sb.Append((string)token["email"]);
                sb.Append((string)token["phone"]);
                sb.Append((string)token["address"]);
                sb.Append((string)token["about"]);
                sb.Append((string)token["registered"]);
                sb.Append((double)token["latitude"]);
                sb.Append((double)token["longitude"]);

                JToken tags = token["tags"];
                foreach (JToken tag in tags)
                {
                    sb.Append((string)tag);
                }
                JToken friends = token["friends"];
                foreach (JToken friend in friends)
                {
                    sb.Append((int)friend["id"]);
                    sb.Append((string)friend["name"]);
                }
                sb.Append((string)token["greeting"]);
                sb.Append((string)token["favoriteFruit"]);

            }
            return sb.ToString();
        }

        private static string ReadHelloWorld(JsonElement obj)
        {
            string message = obj.GetProperty("message").GetString();
            return message;
        }

        private static string ReadJson400KB(JsonElement obj)
        {
            var sb = new StringBuilder();
            int length = obj.GetArrayLength();
            for (int i = 0; i < length; i++)
            {
                sb.Append(obj[i].GetProperty("_id").GetString());
                sb.Append(obj[i].GetProperty("index").GetInt32());
                sb.Append(obj[i].GetProperty("guid").GetString());
                sb.Append(obj[i].GetProperty("isActive").GetBoolean());
                sb.Append(obj[i].GetProperty("balance").GetString());
                sb.Append(obj[i].GetProperty("picture").GetString());
                sb.Append(obj[i].GetProperty("age").GetInt32());
                sb.Append(obj[i].GetProperty("eyeColor").GetString());
                sb.Append(obj[i].GetProperty("name").GetString());
                sb.Append(obj[i].GetProperty("gender").GetString());
                sb.Append(obj[i].GetProperty("company").GetString());
                sb.Append(obj[i].GetProperty("email").GetString());
                sb.Append(obj[i].GetProperty("phone").GetString());
                sb.Append(obj[i].GetProperty("address").GetString());
                sb.Append(obj[i].GetProperty("about").GetString());
                sb.Append(obj[i].GetProperty("registered").GetString());
                sb.Append(obj[i].GetProperty("latitude").GetDouble());
                sb.Append(obj[i].GetProperty("longitude").GetDouble());

                JsonElement tags = obj[i].GetProperty("tags");
                for (int j = 0; j < tags.GetArrayLength(); j++)
                {
                    sb.Append(tags[j].GetString());
                }
                JsonElement friends = obj[i].GetProperty("friends");
                for (int j = 0; j < friends.GetArrayLength(); j++)
                {
                    sb.Append(friends[j].GetProperty("id").GetInt32());
                    sb.Append(friends[j].GetProperty("name").GetString());
                }
                sb.Append(obj[i].GetProperty("greeting").GetString());
                sb.Append(obj[i].GetProperty("favoriteFruit").GetString());
            }
            return sb.ToString();
        }

        // TestCaseType is only used to give the json strings a descriptive name.
        [Theory]
        [MemberData(nameof(TestCases))]
        public static void ParseJson(bool compactData, TestCaseType type, string jsonString)
        {
            // Remove all formatting/indendation
            if (compactData)
            {
                using (JsonTextReader jsonReader = new JsonTextReader(new StringReader(jsonString)))
                {
                    jsonReader.FloatParseHandling = FloatParseHandling.Decimal;
                    JToken jtoken = JToken.ReadFrom(jsonReader);
                    var stringWriter = new StringWriter();
                    using (JsonTextWriter jsonWriter = new JsonTextWriter(stringWriter))
                    {
                        jtoken.WriteTo(jsonWriter);
                        jsonString = stringWriter.ToString();
                    }
                }
            }

            byte[] dataUtf8 = Encoding.UTF8.GetBytes(jsonString);

            using (JsonDocument doc = JsonDocument.Parse(dataUtf8, default))
            {
                using (var stream = new MemoryStream(dataUtf8))
                using (var streamReader = new StreamReader(stream, Encoding.UTF8, false, 1024, true))
                using (JsonTextReader jsonReader = new JsonTextReader(streamReader))
                {
                    JToken jToken = JToken.ReadFrom(jsonReader);

                    string expectedString = "";
                    string actualString = "";

                    if (type == TestCaseType.Json400KB)
                    {
                        expectedString = ReadJson400KB(jToken);
                        actualString = ReadJson400KB(doc.RootElement);
                    }
                    else if (type == TestCaseType.HelloWorld)
                    {
                        expectedString = ReadHelloWorld(jToken);
                        actualString = ReadHelloWorld(doc.RootElement);
                    }

                    Assert.Equal(expectedString, actualString);
                }

                string actual = doc.PrintJson();

                TextReader reader = new StringReader(jsonString);
                string expected = JsonTestHelper.NewtonsoftReturnStringHelper(reader);

                Assert.Equal(expected, actual);

            }
        }

        private static string PrintJson(this JsonDocument document, int sizeHint=0)
        {
            return PrintJson(document.RootElement, sizeHint);
        }

        private static string PrintJson(this JsonElement element, int sizeHint=0)
        {
            StringBuilder sb = new StringBuilder(sizeHint);
            DepthFirstAppend(sb, element);
            return sb.ToString();
        }

        private static void DepthFirstAppend(StringBuilder buf, JsonElement element)
        {
            JsonValueType type = element.Type;

            switch (type)
            {
                case JsonValueType.False:
                case JsonValueType.True:
                case JsonValueType.String:
                case JsonValueType.Number:
                {
                    buf.Append(element.ToString());
                    buf.Append(", ");
                    break;
                }
                case JsonValueType.Object:
                {
                    foreach (JsonProperty prop in element.EnumerateObject())
                    {
                        buf.Append(prop.Name);
                        buf.Append(", ");
                        DepthFirstAppend(buf, prop.Value);
                    }

                    break;
                }
                case JsonValueType.Array:
                {
                    foreach (JsonElement child in element.EnumerateArray())
                    {
                        DepthFirstAppend(buf, child);
                    }

                    break;
                }
            }
        }

        [Theory]
        [InlineData("[{\"arrayWithObjects\":[\"text\",14,[],null,false,{},{\"time\":24},[\"1\",\"2\",\"3\"]]}]")]
        [InlineData("[{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}]")]
        [InlineData("[{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}}]")]
        [InlineData("{\"a\":\"b\"}")]
        [InlineData("{}")]
        [InlineData("[]")]
        public static void CustomParseJson(string jsonString)
        {
            byte[] dataUtf8 = Encoding.UTF8.GetBytes(jsonString);

            using (JsonDocument doc = JsonDocument.Parse(dataUtf8, default))
            {
                string actual = doc.PrintJson();

                TextReader reader = new StringReader(jsonString);
                string expected = JsonTestHelper.NewtonsoftReturnStringHelper(reader);

                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public static void ParseArray()
        {
            ArraySegment<byte> buffer = StringToUtf8BufferWithEmptySpace(SR.SimpleArrayJson, 60);

            using (JsonDocument doc = JsonDocument.Parse(buffer, default))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(2, root.GetArrayLength());

                string phoneNumber = root[0].GetString();
                int age = root[1].GetInt32();

                Assert.Equal("425-214-3151", phoneNumber);
                Assert.Equal(25, age);

                Assert.Throws<IndexOutOfRangeException>(() => root[2]);
            }
        }

        [Fact]
        public static void ParseSimpleObject()
        {
            ArraySegment<byte> buffer = StringToUtf8BufferWithEmptySpace(SR.SimpleObjectJson);

            using (JsonDocument doc = JsonDocument.Parse(buffer, default))
            {
                JsonElement parsedObject = doc.RootElement;

                int age = parsedObject.GetProperty("age").GetInt32();
                string ageString = parsedObject.GetProperty("age").ToString();
                string first = parsedObject.GetProperty("first").GetString();
                string last = parsedObject.GetProperty("last").GetString();
                string phoneNumber = parsedObject.GetProperty("phoneNumber").GetString();
                string street = parsedObject.GetProperty("street").GetString();
                string city = parsedObject.GetProperty("city").GetString();
                int zip = parsedObject.GetProperty("zip").GetInt32();

                Assert.True(parsedObject.TryGetProperty("age", out JsonElement age2));
                Assert.Equal(30, age2.GetInt32());

                Assert.Equal(30, age);
                Assert.Equal("30", ageString);
                Assert.Equal("John", first);
                Assert.Equal("Smith", last);
                Assert.Equal("425-214-3151", phoneNumber);
                Assert.Equal("1 Microsoft Way", street);
                Assert.Equal("Redmond", city);
                Assert.Equal(98052, zip);
            }
        }

        [Fact]
        public static void ParseNestedJson()
        {
            ArraySegment<byte> buffer = StringToUtf8BufferWithEmptySpace(SR.ParseJson);

            using (JsonDocument doc = JsonDocument.Parse(buffer, default))
            {
                JsonElement parsedObject = doc.RootElement;

                Assert.Equal(1, parsedObject.GetArrayLength());
                JsonElement person = parsedObject[0];
                double age = person.GetProperty("age").GetDouble();
                string first = person.GetProperty("first").GetString();
                string last = person.GetProperty("last").GetString();
                JsonElement phoneNums = person.GetProperty("phoneNumbers");
                Assert.Equal(2, phoneNums.GetArrayLength());
                string phoneNum1 = phoneNums[0].GetString();
                string phoneNum2 = phoneNums[1].GetString();
                JsonElement address = person.GetProperty("address");
                string street = address.GetProperty("street").GetString();
                string city = address.GetProperty("city").GetString();
                double zipCode = address.GetProperty("zip").GetDouble();

                Assert.Equal(30, age);
                Assert.Equal("John", first);
                Assert.Equal("Smith", last);
                Assert.Equal("425-000-1212", phoneNum1);
                Assert.Equal("425-000-1213", phoneNum2);
                Assert.Equal("1 Microsoft Way", street);
                Assert.Equal("Redmond", city);
                Assert.Equal(98052, zipCode);

                Assert.Throws<InvalidOperationException>(() => person.GetArrayLength());
                Assert.Throws<IndexOutOfRangeException>(() => phoneNums[2]);
                Assert.Throws<InvalidOperationException>(() => phoneNums.GetProperty("2"));
                Assert.Throws<KeyNotFoundException>(() => address.GetProperty("2"));
                Assert.Throws<InvalidOperationException>(() => address.GetProperty("city").GetDouble());
                Assert.Throws<InvalidOperationException>(() => address.GetProperty("city").GetBoolean());
                Assert.Throws<InvalidOperationException>(() => address.GetProperty("zip").GetString());
                Assert.Throws<InvalidOperationException>(() => person.GetProperty("phoneNumbers").GetString());
                Assert.Throws<InvalidOperationException>(() => person.GetString());
            }
        }

        [Fact]
        public static void ParseBoolean()
        {
            ArraySegment<byte> buffer = StringToUtf8BufferWithEmptySpace("[true,false]", 60);

            using (JsonDocument doc = JsonDocument.Parse(buffer, default))
            {
                JsonElement parsedObject = doc.RootElement;
                bool first = parsedObject[0].GetBoolean();
                bool second = parsedObject[1].GetBoolean();
                Assert.Equal(true, first);
                Assert.Equal(false, second);
            }
        }

        [Fact]
        public static void JsonArrayToString()
        {
            ArraySegment<byte> buffer = StringToUtf8BufferWithEmptySpace(SR.ParseJson);

            using (JsonDocument doc = JsonDocument.Parse(buffer, default))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonValueType.Array, root.Type);
                Assert.Equal(SR.ParseJson, root.ToString());
            }
        }

        [Fact]
        public static void JsonObjectToString()
        {
            ArraySegment<byte> buffer = StringToUtf8BufferWithEmptySpace(SR.BasicJson);

            using (JsonDocument doc = JsonDocument.Parse(buffer, default))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonValueType.Object, root.Type);
                Assert.Equal(SR.BasicJson, root.ToString());
            }
        }

        [Fact]
        public static void MixedArrayIndexing()
        {
            // The root object is an array with "complex" children
            // root[0] is a number (simple single forward)
            // root[1] is an object which needs to account for the start entry, the children, and end.
            // root[2] is the target inner array
            // root[3] is a simple value past two complex values
            //
            // Within root[2] the array has only simple values, so it uses a different indexing algorithm.
            const string json = " [ 6, { \"hi\": \"mom\" }, [ \"425-214-3151\", 25 ], null ] ";

            using (JsonDocument doc = JsonDocument.Parse(json))
            {
                JsonElement root = doc.RootElement;
                JsonElement target = root[2];

                Assert.Equal(2, target.GetArrayLength());

                string phoneNumber = target[0].GetString();
                int age = target[1].GetInt32();

                Assert.Equal("425-214-3151", phoneNumber);
                Assert.Equal(25, age);
                Assert.Equal(JsonValueType.Null, root[3].Type);

                Assert.Throws<IndexOutOfRangeException>(() => root[4]);
            }
        }

        [Theory]
        [InlineData(0)]
        [InlineData(int.MaxValue)]
        [InlineData(int.MinValue)]
        public static void ReadSmallInteger(int value)
        {
            double expectedDouble = value;
            float expectedFloat = value;
            decimal expectedDecimal = value;

            using (JsonDocument doc = JsonDocument.Parse("    " + value + "  "))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonValueType.Number, root.Type);

                Assert.True(root.TryGetSingle(out float floatVal));
                Assert.Equal(expectedFloat, floatVal);

                Assert.True(root.TryGetDouble(out double doubleVal));
                Assert.Equal(expectedDouble, doubleVal);

                Assert.True(root.TryGetDecimal(out decimal decimalVal));
                Assert.Equal(expectedDecimal, decimalVal);

                Assert.True(root.TryGetInt32(out int intVal));
                Assert.Equal(value, intVal);

                Assert.True(root.TryGetInt64(out long longVal));
                Assert.Equal(value, longVal);

                Assert.Equal(expectedFloat, root.GetSingle());
                Assert.Equal(expectedDouble, root.GetDouble());
                Assert.Equal(expectedDecimal, root.GetDecimal());
                Assert.Equal(value, root.GetInt32());
                Assert.Equal(value, root.GetInt64());

                if (value >= 0)
                {
                    uint expectedUInt = (uint)value;
                    ulong expectedULong = (ulong)value;

                    Assert.True(root.TryGetUInt32(out uint uintVal));
                    Assert.Equal(expectedUInt, uintVal);

                    Assert.True(root.TryGetUInt64(out ulong ulongVal));
                    Assert.Equal(expectedULong, ulongVal);

                    Assert.Equal(expectedUInt, root.GetUInt32());
                    Assert.Equal(expectedULong, root.GetUInt64());
                }
                else
                {
                    Assert.False(root.TryGetUInt32(out uint uintValue));
                    Assert.Equal(0U, uintValue);

                    Assert.False(root.TryGetUInt64(out ulong ulongValue));
                    Assert.Equal(0UL, ulongValue);

                    Assert.Throws<FormatException>(() => root.GetUInt32());
                    Assert.Throws<FormatException>(() => root.GetUInt64());
                }

                Assert.Throws<InvalidOperationException>(() => root.GetString());
                Assert.Throws<InvalidOperationException>(() => root.GetArrayLength());
                Assert.Throws<InvalidOperationException>(() => root.EnumerateArray());
                Assert.Throws<InvalidOperationException>(() => root.EnumerateObject());
                Assert.Throws<InvalidOperationException>(() => root.GetBoolean());
            }
        }

        [Theory]
        [InlineData((long)int.MaxValue + 1)]
        [InlineData((long)uint.MaxValue)]
        [InlineData(long.MaxValue)]
        [InlineData((long)int.MinValue - 1)]
        [InlineData(long.MinValue)]
        public static void ReadMediumInteger(long value)
        {
            double expectedDouble = value;
            float expectedFloat = value;
            decimal expectedDecimal = value;

            using (JsonDocument doc = JsonDocument.Parse("    " + value + "  "))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonValueType.Number, root.Type);

                Assert.True(root.TryGetSingle(out float floatVal));
                Assert.Equal(expectedFloat, floatVal);

                Assert.True(root.TryGetDouble(out double doubleVal));
                Assert.Equal(expectedDouble, doubleVal);

                Assert.True(root.TryGetDecimal(out decimal decimalVal));
                Assert.Equal(expectedDecimal, decimalVal);

                Assert.False(root.TryGetInt32(out int intVal));
                Assert.Equal(0, intVal);

                Assert.True(root.TryGetInt64(out long longVal));
                Assert.Equal(value, longVal);

                Assert.Equal(expectedFloat, root.GetSingle());
                Assert.Equal(expectedDouble, root.GetDouble());
                Assert.Equal(expectedDecimal, root.GetDecimal());
                Assert.Throws<FormatException>(() => root.GetInt32());
                Assert.Equal(value, root.GetInt64());

                if (value >= 0)
                {
                    if (value <= uint.MaxValue)
                    {
                        uint expectedUInt = (uint)value;
                        Assert.True(root.TryGetUInt32(out uint uintVal));
                        Assert.Equal(expectedUInt, uintVal);

                        Assert.Equal(expectedUInt, root.GetUInt64());
                    }
                    else
                    {
                        Assert.False(root.TryGetUInt32(out uint uintValue));
                        Assert.Equal(0U, uintValue);

                        Assert.Throws<FormatException>(() => root.GetUInt32());
                    }

                    ulong expectedULong = (ulong)value;
                    Assert.True(root.TryGetUInt64(out ulong ulongVal));
                    Assert.Equal(expectedULong, ulongVal);

                    Assert.Equal(expectedULong, root.GetUInt64());
                }
                else
                {
                    Assert.False(root.TryGetUInt32(out uint uintValue));
                    Assert.Equal(0U, uintValue);

                    Assert.False(root.TryGetUInt64(out ulong ulongValue));
                    Assert.Equal(0UL, ulongValue);

                    Assert.Throws<FormatException>(() => root.GetUInt32());
                    Assert.Throws<FormatException>(() => root.GetUInt64());
                }

                Assert.Throws<InvalidOperationException>(() => root.GetString());
                Assert.Throws<InvalidOperationException>(() => root.GetArrayLength());
                Assert.Throws<InvalidOperationException>(() => root.EnumerateArray());
                Assert.Throws<InvalidOperationException>(() => root.EnumerateObject());
                Assert.Throws<InvalidOperationException>(() => root.GetBoolean());
            }
        }

        [Theory]
        [InlineData((ulong)long.MaxValue + 1)]
        [InlineData(ulong.MaxValue)]
        public static void ReadLargeInteger(ulong value)
        {
            double expectedDouble = value;
            float expectedFloat = value;
            decimal expectedDecimal = value;

            using (JsonDocument doc = JsonDocument.Parse("    " + value + "  "))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonValueType.Number, root.Type);

                Assert.True(root.TryGetSingle(out float floatVal));
                Assert.Equal(expectedFloat, floatVal);

                Assert.True(root.TryGetDouble(out double doubleVal));
                Assert.Equal(expectedDouble, doubleVal);

                Assert.True(root.TryGetDecimal(out decimal decimalVal));
                Assert.Equal(expectedDecimal, decimalVal);

                Assert.False(root.TryGetInt32(out int intVal));
                Assert.Equal(0, intVal);

                Assert.False(root.TryGetUInt32(out uint uintVal));
                Assert.Equal(0U, uintVal);

                Assert.False(root.TryGetInt64(out long longVal));
                Assert.Equal(0L, longVal);

                Assert.Equal(expectedFloat, root.GetSingle());
                Assert.Equal(expectedDouble, root.GetDouble());
                Assert.Equal(expectedDecimal, root.GetDecimal());
                Assert.Throws<FormatException>(() => root.GetInt32());
                Assert.Throws<FormatException>(() => root.GetUInt32());
                Assert.Throws<FormatException>(() => root.GetInt64());

                Assert.True(root.TryGetUInt64(out ulong ulongVal));
                Assert.Equal(value, ulongVal);

                Assert.Equal(value, root.GetUInt64());

                Assert.Throws<InvalidOperationException>(() => root.GetString());
                Assert.Throws<InvalidOperationException>(() => root.GetArrayLength());
                Assert.Throws<InvalidOperationException>(() => root.EnumerateArray());
                Assert.Throws<InvalidOperationException>(() => root.EnumerateObject());
                Assert.Throws<InvalidOperationException>(() => root.GetBoolean());
            }
        }

        [Fact]
        public static void ReadTooLargeInteger()
        {
            float expectedFloat = ulong.MaxValue;
            double expectedDouble = ulong.MaxValue;
            decimal expectedDecimal = ulong.MaxValue;
            expectedDouble *= 10;
            expectedFloat *= 10;
            expectedDecimal *= 10;

            using (JsonDocument doc = JsonDocument.Parse("    " + ulong.MaxValue + "0  ", default))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonValueType.Number, root.Type);

                Assert.True(root.TryGetSingle(out float floatVal));
                Assert.Equal(expectedFloat, floatVal);

                Assert.True(root.TryGetDouble(out double doubleVal));
                Assert.Equal(expectedDouble, doubleVal);

                Assert.True(root.TryGetDecimal(out decimal decimalVal));
                Assert.Equal(expectedDecimal, decimalVal);

                Assert.False(root.TryGetInt32(out int intVal));
                Assert.Equal(0, intVal);

                Assert.False(root.TryGetUInt32(out uint uintVal));
                Assert.Equal(0U, uintVal);

                Assert.False(root.TryGetInt64(out long longVal));
                Assert.Equal(0L, longVal);

                Assert.False(root.TryGetUInt64(out ulong ulongVal));
                Assert.Equal(0UL, ulongVal);

                Assert.Equal(expectedFloat, root.GetSingle());
                Assert.Equal(expectedDouble, root.GetDouble());
                Assert.Equal(expectedDecimal, root.GetDecimal());
                Assert.Throws<FormatException>(() => root.GetInt32());
                Assert.Throws<FormatException>(() => root.GetUInt32());
                Assert.Throws<FormatException>(() => root.GetInt64());
                Assert.Throws<FormatException>(() => root.GetUInt64());

                Assert.Throws<InvalidOperationException>(() => root.GetString());
                Assert.Throws<InvalidOperationException>(() => root.GetArrayLength());
                Assert.Throws<InvalidOperationException>(() => root.EnumerateArray());
                Assert.Throws<InvalidOperationException>(() => root.EnumerateObject());
                Assert.Throws<InvalidOperationException>(() => root.GetBoolean());
            }
        }

        public static IEnumerable<object[]> NonIntegerCases
        {
            get
            {
                yield return new object[] { "1e+1", 10.0, 10.0f, 10m };
                yield return new object[] { "1.1e-0", 1.1, 1.1f, 1.1m };
                yield return new object[] { "3.14159", 3.14159, 3.14159f, 3.14159m };
                yield return new object[] { "1e-10", 1e-10, 1e-10f, 1e-10m };
                yield return new object[] { "1234567.15", 1234567.15, 1234567.13f, 1234567.15m };
            }
        }

        [Theory]
        [MemberData(nameof(NonIntegerCases))]
        public static void ReadNonInteger(string str, double expectedDouble, float expectedFloat, decimal expectedDecimal)
        {
            using (JsonDocument doc = JsonDocument.Parse("    " + str + "  "))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonValueType.Number, root.Type);

                Assert.True(root.TryGetSingle(out float floatVal));
                Assert.Equal(expectedFloat, floatVal);

                Assert.True(root.TryGetDouble(out double doubleVal));
                Assert.Equal(expectedDouble, doubleVal);

                Assert.True(root.TryGetDecimal(out decimal decimalVal));
                Assert.Equal(expectedDecimal, decimalVal);

                Assert.False(root.TryGetInt32(out int intVal));
                Assert.Equal(0, intVal);

                Assert.False(root.TryGetInt64(out long longVal));
                Assert.Equal(0L, longVal);

                Assert.False(root.TryGetUInt64(out ulong ulongVal));
                Assert.Equal(0UL, ulongVal);

                Assert.Equal(expectedFloat, root.GetSingle());
                Assert.Equal(expectedDouble, root.GetDouble());
                Assert.Equal(expectedDecimal, root.GetDecimal());
                Assert.Throws<FormatException>(() => root.GetInt32());
                Assert.Throws<FormatException>(() => root.GetInt64());
                Assert.Throws<FormatException>(() => root.GetUInt64());

                Assert.Throws<InvalidOperationException>(() => root.GetString());
                Assert.Throws<InvalidOperationException>(() => root.GetArrayLength());
                Assert.Throws<InvalidOperationException>(() => root.EnumerateArray());
                Assert.Throws<InvalidOperationException>(() => root.EnumerateObject());
                Assert.Throws<InvalidOperationException>(() => root.GetBoolean());
            }
        }

        [Fact]
        public static void ReadTooPreciseDouble()
        {
            // If https://github.com/dotnet/corefx/issues/33997 gets resolved as the reader throwing,
            // this test would need to expect FormatException from GetDouble, and false from TryGet.
            using (JsonDocument doc = JsonDocument.Parse("    1e+100000002"))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonValueType.Number, root.Type);

                Assert.True(root.TryGetSingle(out float floatVal));
                Assert.Equal(float.PositiveInfinity, floatVal);

                Assert.True(root.TryGetDouble(out double doubleVal));
                Assert.Equal(double.PositiveInfinity, doubleVal);

                Assert.False(root.TryGetDecimal(out decimal decimalVal));
                Assert.Equal(0m, decimalVal);

                Assert.False(root.TryGetInt32(out int intVal));
                Assert.Equal(0, intVal);

                Assert.False(root.TryGetInt64(out long longVal));
                Assert.Equal(0L, longVal);

                Assert.False(root.TryGetUInt64(out ulong ulongVal));
                Assert.Equal(0UL, ulongVal);

                Assert.Equal(float.PositiveInfinity, root.GetSingle());
                Assert.Equal(double.PositiveInfinity, root.GetDouble());
                Assert.Throws<FormatException>(() => root.GetDecimal());
                Assert.Throws<FormatException>(() => root.GetInt32());
                Assert.Throws<FormatException>(() => root.GetInt64());
                Assert.Throws<FormatException>(() => root.GetUInt64());

                Assert.Throws<InvalidOperationException>(() => root.GetString());
                Assert.Throws<InvalidOperationException>(() => root.GetArrayLength());
                Assert.Throws<InvalidOperationException>(() => root.EnumerateArray());
                Assert.Throws<InvalidOperationException>(() => root.EnumerateObject());
                Assert.Throws<InvalidOperationException>(() => root.GetBoolean());
            }
        }

        [Fact]
        public static void ReadArrayWithComments()
        {
            // If https://github.com/dotnet/corefx/issues/33997 gets resolved as the reader throwing,
            // this test would need to expect FormatException from GetDouble, and false from TryGet.
            JsonReaderOptions options = new JsonReaderOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
            };

            using (JsonDocument doc = JsonDocument.Parse(
                "[ 0, 1, 2, 3/*.14159*/           , /* 42, 11, hut, hut, hike! */ 4 ]",
                options))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonValueType.Array, root.Type);
                Assert.Equal(5, root.GetArrayLength());

                for (int i = root.GetArrayLength() - 1; i >= 0; i--)
                {
                    Assert.Equal(i, root[i].GetInt32());
                }

                int val = 0;

                foreach (JsonElement element in root.EnumerateArray())
                {
                    Assert.Equal(val, element.GetInt32());
                    val++;
                }

                Assert.Throws<InvalidOperationException>(() => root.GetDouble());
                Assert.Throws<InvalidOperationException>(() => root.TryGetDouble(out double _));
                Assert.Throws<InvalidOperationException>(() => root.GetInt32());
                Assert.Throws<InvalidOperationException>(() => root.TryGetInt32(out int _));
                Assert.Throws<InvalidOperationException>(() => root.GetInt64());
                Assert.Throws<InvalidOperationException>(() => root.TryGetInt64(out long _));
                Assert.Throws<InvalidOperationException>(() => root.GetUInt64());
                Assert.Throws<InvalidOperationException>(() => root.TryGetUInt64(out ulong _));
                Assert.Throws<InvalidOperationException>(() => root.GetString());
                Assert.Throws<InvalidOperationException>(() => root.EnumerateObject());
                Assert.Throws<InvalidOperationException>(() => root.GetBoolean());
            }
        }

        [Fact]
        public static void CheckUseAfterDispose()
        {
            using (JsonDocument doc = JsonDocument.Parse("true", default))
            {
                JsonElement root = doc.RootElement;
                doc.Dispose();

                Assert.Throws<ObjectDisposedException>(() => root.Type);
                Assert.Throws<ObjectDisposedException>(() => root.GetArrayLength());
                Assert.Throws<ObjectDisposedException>(() => root.EnumerateArray());
                Assert.Throws<ObjectDisposedException>(() => root.EnumerateObject());
                Assert.Throws<ObjectDisposedException>(() => root.GetDouble());
                Assert.Throws<ObjectDisposedException>(() => root.TryGetDouble(out double _));
                Assert.Throws<ObjectDisposedException>(() => root.GetInt32());
                Assert.Throws<ObjectDisposedException>(() => root.TryGetInt32(out int _));
                Assert.Throws<ObjectDisposedException>(() => root.GetInt64());
                Assert.Throws<ObjectDisposedException>(() => root.TryGetInt64(out long _));
                Assert.Throws<ObjectDisposedException>(() => root.GetUInt64());
                Assert.Throws<ObjectDisposedException>(() => root.TryGetUInt64(out ulong _));
                Assert.Throws<ObjectDisposedException>(() => root.GetString());
                Assert.Throws<ObjectDisposedException>(() => root.GetBoolean());
            }
        }

        [Fact]
        public static void CheckUseDefault()
        {
            JsonElement root = default;

            Assert.Equal(JsonValueType.Undefined, root.Type);

            Assert.Throws<InvalidOperationException>(() => root.GetArrayLength());
            Assert.Throws<InvalidOperationException>(() => root.EnumerateArray());
            Assert.Throws<InvalidOperationException>(() => root.EnumerateObject());
            Assert.Throws<InvalidOperationException>(() => root.GetDouble());
            Assert.Throws<InvalidOperationException>(() => root.TryGetDouble(out double _));
            Assert.Throws<InvalidOperationException>(() => root.GetInt32());
            Assert.Throws<InvalidOperationException>(() => root.TryGetInt32(out int _));
            Assert.Throws<InvalidOperationException>(() => root.GetInt64());
            Assert.Throws<InvalidOperationException>(() => root.TryGetInt64(out long _));
            Assert.Throws<InvalidOperationException>(() => root.GetUInt64());
            Assert.Throws<InvalidOperationException>(() => root.TryGetUInt64(out ulong _));
            Assert.Throws<InvalidOperationException>(() => root.GetString());
            Assert.Throws<InvalidOperationException>(() => root.GetBoolean());
        }

        [Fact]
        public static void CheckInvalidString()
        {
            Assert.Throws<EncoderFallbackException>(() => JsonDocument.Parse("{ \"unpaired\uDFFE\": true }", default));
        }

        [Theory]
        [InlineData("\"hello\"    ", "hello")]
        [InlineData("    null     ", (string)null)]
        // TODO(#33292) [InlineData("\"\\u0030\\u0031\"", "31")]
        public static void ReadString(string json, string expectedValue)
        {
            using (JsonDocument doc = JsonDocument.Parse(json))
            {
                Assert.Equal(expectedValue, doc.RootElement.GetString());
            }
        }

        [Fact]
        public static void TryGetProperty_NoProperty()
        {
            using (JsonDocument doc = JsonDocument.Parse(" { \"hi\": \"there\" }"))
            {
                JsonElement root = doc.RootElement;

                const string NotPresent = "Not Present";
                byte[] notPresentUtf8 = Encoding.UTF8.GetBytes(NotPresent);

                Assert.False(root.TryGetProperty(NotPresent, out _));
                Assert.False(root.TryGetProperty(NotPresent.AsSpan(), out _));
                Assert.False(root.TryGetProperty(notPresentUtf8, out _));
                Assert.False(root.TryGetProperty(new string('z', 512), out _));

                Assert.Throws<KeyNotFoundException>(() => root.GetProperty(NotPresent));
                Assert.Throws<KeyNotFoundException>(() => root.GetProperty(NotPresent.AsSpan()));
                Assert.Throws<KeyNotFoundException>(() => root.GetProperty(notPresentUtf8));
                Assert.Throws<KeyNotFoundException>(() => root.GetProperty(new string('z', 512)));
            }
        }

        [Theory]
        [InlineData("")]
        [InlineData("    ")]
        [InlineData("1 2")]
        [InlineData("[ 1")]
        public static void CheckUnparsable(string json)
        {
            Assert.Throws<JsonReaderException>(() => JsonDocument.Parse(json));

            byte[] utf8 = Encoding.UTF8.GetBytes(json);
            Assert.Throws<JsonReaderException>(() => JsonDocument.Parse(utf8));

            ReadOnlySequence<byte> singleSeq = new ReadOnlySequence<byte>(utf8);
            Assert.Throws<JsonReaderException>(() => JsonDocument.Parse(singleSeq));

            ReadOnlySequence<byte> multiSegment = SegmentInto(utf8, 6);
            Assert.Throws<JsonReaderException>(() => JsonDocument.Parse(multiSegment));
        }

        [Fact]
        public static void CheckParseDepth()
        {
            const int OkayCount = 64;
            string okayJson = new string('[', OkayCount) + "1" + new string(']', OkayCount);

            using (JsonDocument doc = JsonDocument.Parse(okayJson))
            {
                JsonElement root = doc.RootElement;
                Assert.Equal(JsonValueType.Array, root.Type);
            }

            string badJson = $"[{okayJson}]";

            Assert.Throws<JsonReaderException>(() => JsonDocument.Parse(badJson));
        }

        [Fact]
        public static void EnableComments()
        {
            string json = "3";
            JsonReaderOptions options = new JsonReaderOptions
            {
                CommentHandling = JsonCommentHandling.Allow,
            };

            AssertExtensions.Throws<ArgumentException>(
                "readerOptions",
                () => JsonDocument.Parse(json, options));

            byte[] utf8 = Encoding.UTF8.GetBytes(json);
            AssertExtensions.Throws<ArgumentException>(
                "readerOptions",
                () => JsonDocument.Parse(utf8, options));

            ReadOnlySequence<byte> singleSeq = new ReadOnlySequence<byte>(utf8);
            AssertExtensions.Throws<ArgumentException>(
                "readerOptions",
                () => JsonDocument.Parse(singleSeq, options));

            ReadOnlySequence<byte> multiSegment = SegmentInto(utf8, 6);
            AssertExtensions.Throws<ArgumentException>(
                "readerOptions",
                () => JsonDocument.Parse(multiSegment, options));
        }

        [Fact]
        public static void GetPropertyByNullName()
        {
            using (JsonDocument doc = JsonDocument.Parse("{ }"))
            {
                AssertExtensions.Throws<ArgumentNullException>(
                    "propertyName",
                    () => doc.RootElement.GetProperty((string)null));

                AssertExtensions.Throws<ArgumentNullException>(
                    "propertyName",
                    () => doc.RootElement.TryGetProperty((string)null, out _));
            }
        }

        [Theory]
        [InlineData("short")]
        [InlineData("thisValueIsLongerThan86CharsSoWeDeferTheTranscodingUntilWeFindAViableCandidateAsAPropertyMatch")]
        public static void GetPropertyFindsLast(string propertyName)
        {
            string json = $"{{ \"{propertyName}\": 1, \"{propertyName}\": 2, \"nope\": -1, \"{propertyName}\": 3 }}";

            using (JsonDocument doc = JsonDocument.Parse(json))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(3, root.GetProperty(propertyName).GetInt32());
                Assert.Equal(3, root.GetProperty(propertyName.AsSpan()).GetInt32());
                Assert.Equal(3, root.GetProperty(Encoding.UTF8.GetBytes(propertyName)).GetInt32());
            }
        }

        [Fact]
        public static void ArrayEnumeratorIndependentWalk()
        {
            using (JsonDocument doc = JsonDocument.Parse("[0, 1, 2, 3, 4, 5]"))
            {
                JsonElement root = doc.RootElement;
                JsonElement.ArrayEnumerator structEnumerable = root.EnumerateArray();
                IEnumerable<JsonElement> strongBoxedEnumerable = root.EnumerateArray();
                IEnumerable weakBoxedEnumerable = root.EnumerateArray();

                JsonElement.ArrayEnumerator structEnumerator = structEnumerable.GetEnumerator();
                IEnumerator<JsonElement> strongBoxedEnumerator = strongBoxedEnumerable.GetEnumerator();
                IEnumerator weakBoxedEnumerator = weakBoxedEnumerable.GetEnumerator();

                Assert.True(structEnumerator.MoveNext());
                Assert.True(strongBoxedEnumerator.MoveNext());
                Assert.True(weakBoxedEnumerator.MoveNext());

                Assert.Equal(0, structEnumerator.Current.GetInt32());
                Assert.Equal(0, strongBoxedEnumerator.Current.GetInt32());
                Assert.Equal(0, ((JsonElement)weakBoxedEnumerator.Current).GetInt32());

                Assert.True(structEnumerator.MoveNext());
                Assert.True(strongBoxedEnumerator.MoveNext());
                Assert.True(weakBoxedEnumerator.MoveNext());

                Assert.Equal(1, structEnumerator.Current.GetInt32());
                Assert.Equal(1, strongBoxedEnumerator.Current.GetInt32());
                Assert.Equal(1, ((JsonElement)weakBoxedEnumerator.Current).GetInt32());

                int test = 0;

                foreach (JsonElement element in structEnumerable)
                {
                    Assert.Equal(test, element.GetInt32());
                    test++;
                }

                test = 0;

                foreach (JsonElement element in structEnumerable)
                {
                    Assert.Equal(test, element.GetInt32());
                    test++;
                }

                test = 0;

                foreach (JsonElement element in strongBoxedEnumerable)
                {
                    Assert.Equal(test, element.GetInt32());
                    test++;
                }

                test = 0;

                foreach (JsonElement element in strongBoxedEnumerable)
                {
                    Assert.Equal(test, element.GetInt32());
                    test++;
                }

                test = 0;

                foreach (JsonElement element in weakBoxedEnumerable)
                {
                    Assert.Equal(test, element.GetInt32());
                    test++;
                }

                test = 0;

                foreach (JsonElement element in weakBoxedEnumerable)
                {
                    Assert.Equal(test, element.GetInt32());
                    test++;
                }

                Assert.True(structEnumerator.MoveNext());
                Assert.Equal(2, structEnumerator.Current.GetInt32());

                Assert.True(structEnumerator.MoveNext());
                Assert.Equal(3, structEnumerator.Current.GetInt32());

                Assert.True(strongBoxedEnumerator.MoveNext());
                Assert.Equal(2, strongBoxedEnumerator.Current.GetInt32());

                Assert.True(structEnumerator.MoveNext());
                Assert.Equal(4, structEnumerator.Current.GetInt32());

                Assert.True(structEnumerator.MoveNext());
                Assert.Equal(5, structEnumerator.Current.GetInt32());

                Assert.True(strongBoxedEnumerator.MoveNext());
                Assert.Equal(3, strongBoxedEnumerator.Current.GetInt32());

                Assert.True(weakBoxedEnumerator.MoveNext());
                Assert.Equal(2, ((JsonElement)weakBoxedEnumerator.Current).GetInt32());

                Assert.False(structEnumerator.MoveNext());

                Assert.True(strongBoxedEnumerator.MoveNext());
                Assert.Equal(4, strongBoxedEnumerator.Current.GetInt32());

                Assert.True(strongBoxedEnumerator.MoveNext());
                Assert.Equal(5, strongBoxedEnumerator.Current.GetInt32());

                Assert.True(weakBoxedEnumerator.MoveNext());
                Assert.Equal(3, ((JsonElement)weakBoxedEnumerator.Current).GetInt32());

                Assert.True(weakBoxedEnumerator.MoveNext());
                Assert.Equal(4, ((JsonElement)weakBoxedEnumerator.Current).GetInt32());

                Assert.False(structEnumerator.MoveNext());
                Assert.False(strongBoxedEnumerator.MoveNext());

                Assert.True(weakBoxedEnumerator.MoveNext());
                Assert.Equal(5, ((JsonElement)weakBoxedEnumerator.Current).GetInt32());

                Assert.False(weakBoxedEnumerator.MoveNext());
                Assert.False(structEnumerator.MoveNext());
                Assert.False(strongBoxedEnumerator.MoveNext());
                Assert.False(weakBoxedEnumerator.MoveNext());
            }
        }

        [Fact]
        public static void DefaultArrayEnumeratorDoesNotThrow()
        {
            JsonElement.ArrayEnumerator enumerable = default;
            JsonElement.ArrayEnumerator enumerator = enumerable.GetEnumerator();
            JsonElement.ArrayEnumerator defaultEnumerator = default;

            Assert.Equal(JsonValueType.Undefined, enumerable.Current.Type);
            Assert.Equal(JsonValueType.Undefined, enumerator.Current.Type);

            Assert.False(enumerable.MoveNext());
            Assert.False(enumerable.MoveNext());
            Assert.False(defaultEnumerator.MoveNext());
        }

        [Fact]
        public static void ObjectEnumeratorIndependentWalk()
        {
            const string json = @"
{
  ""name0"": 0,
  ""name1"": 1,
  ""name2"": 2,
  ""name3"": 3,
  ""name4"": 4,
  ""name5"": 5
}";
            using (JsonDocument doc = JsonDocument.Parse(json))
            {
                JsonElement root = doc.RootElement;
                JsonElement.ObjectEnumerator structEnumerable = root.EnumerateObject();
                IEnumerable<JsonProperty> strongBoxedEnumerable = root.EnumerateObject();
                IEnumerable weakBoxedEnumerable = root.EnumerateObject();

                JsonElement.ObjectEnumerator structEnumerator = structEnumerable.GetEnumerator();
                IEnumerator<JsonProperty> strongBoxedEnumerator = strongBoxedEnumerable.GetEnumerator();
                IEnumerator weakBoxedEnumerator = weakBoxedEnumerable.GetEnumerator();

                Assert.True(structEnumerator.MoveNext());
                Assert.True(strongBoxedEnumerator.MoveNext());
                Assert.True(weakBoxedEnumerator.MoveNext());

                Assert.Equal("name0", structEnumerator.Current.Name);
                Assert.Equal(0, structEnumerator.Current.Value.GetInt32());
                Assert.Equal("name0", strongBoxedEnumerator.Current.Name);
                Assert.Equal(0, strongBoxedEnumerator.Current.Value.GetInt32());
                Assert.Equal("name0", ((JsonProperty)weakBoxedEnumerator.Current).Name);
                Assert.Equal(0, ((JsonProperty)weakBoxedEnumerator.Current).Value.GetInt32());

                Assert.True(structEnumerator.MoveNext());
                Assert.True(strongBoxedEnumerator.MoveNext());
                Assert.True(weakBoxedEnumerator.MoveNext());

                Assert.Equal(1, structEnumerator.Current.Value.GetInt32());
                Assert.Equal(1, strongBoxedEnumerator.Current.Value.GetInt32());
                Assert.Equal(1, ((JsonProperty)weakBoxedEnumerator.Current).Value.GetInt32());

                int test = 0;

                foreach (JsonProperty property in structEnumerable)
                {
                    Assert.Equal("name" + test, property.Name);
                    Assert.Equal(test, property.Value.GetInt32());
                    test++;
                }

                test = 0;

                foreach (JsonProperty property in structEnumerable)
                {
                    Assert.Equal("name" + test, property.Name);
                    Assert.Equal(test, property.Value.GetInt32());
                    test++;
                }

                test = 0;

                foreach (JsonProperty property in strongBoxedEnumerable)
                {
                    Assert.Equal("name" + test, property.Name);
                    Assert.Equal(test, property.Value.GetInt32());
                    test++;
                }

                test = 0;

                foreach (JsonProperty property in strongBoxedEnumerable)
                {
                    Assert.Equal("name" + test, property.Name);
                    Assert.Equal(test, property.Value.GetInt32());
                    test++;
                }

                test = 0;

                foreach (JsonProperty property in weakBoxedEnumerable)
                {
                    Assert.Equal("name" + test, property.Name);
                    Assert.Equal(test, property.Value.GetInt32());
                    test++;
                }

                test = 0;

                foreach (JsonProperty property in weakBoxedEnumerable)
                {
                    Assert.Equal("name" + test, property.Name);
                    Assert.Equal(test, property.Value.GetInt32());
                    test++;
                }

                Assert.True(structEnumerator.MoveNext());
                Assert.Equal("name2", structEnumerator.Current.Name);
                Assert.Equal(2, structEnumerator.Current.Value.GetInt32());

                Assert.True(structEnumerator.MoveNext());
                Assert.Equal("name3", structEnumerator.Current.Name);
                Assert.Equal(3, structEnumerator.Current.Value.GetInt32());

                Assert.True(strongBoxedEnumerator.MoveNext());
                Assert.Equal("name2", strongBoxedEnumerator.Current.Name);
                Assert.Equal(2, strongBoxedEnumerator.Current.Value.GetInt32());

                Assert.True(structEnumerator.MoveNext());
                Assert.Equal("name4", structEnumerator.Current.Name);
                Assert.Equal(4, structEnumerator.Current.Value.GetInt32());

                Assert.True(structEnumerator.MoveNext());
                Assert.Equal("name5", structEnumerator.Current.Name);
                Assert.Equal(5, structEnumerator.Current.Value.GetInt32());

                Assert.True(strongBoxedEnumerator.MoveNext());
                Assert.Equal("name3", strongBoxedEnumerator.Current.Name);
                Assert.Equal(3, strongBoxedEnumerator.Current.Value.GetInt32());

                Assert.True(weakBoxedEnumerator.MoveNext());
                Assert.Equal("name2", ((JsonProperty)weakBoxedEnumerator.Current).Name);
                Assert.Equal(2, ((JsonProperty)weakBoxedEnumerator.Current).Value.GetInt32());

                Assert.False(structEnumerator.MoveNext());

                Assert.True(strongBoxedEnumerator.MoveNext());
                Assert.Equal("name4", strongBoxedEnumerator.Current.Name);
                Assert.Equal(4, strongBoxedEnumerator.Current.Value.GetInt32());

                Assert.True(strongBoxedEnumerator.MoveNext());
                Assert.Equal("name5", strongBoxedEnumerator.Current.Name);
                Assert.Equal(5, strongBoxedEnumerator.Current.Value.GetInt32());

                Assert.True(weakBoxedEnumerator.MoveNext());
                Assert.Equal("name3", ((JsonProperty)weakBoxedEnumerator.Current).Name);
                Assert.Equal(3, ((JsonProperty)weakBoxedEnumerator.Current).Value.GetInt32());

                Assert.True(weakBoxedEnumerator.MoveNext());
                Assert.Equal("name4", ((JsonProperty)weakBoxedEnumerator.Current).Name);
                Assert.Equal(4, ((JsonProperty)weakBoxedEnumerator.Current).Value.GetInt32());

                Assert.False(structEnumerator.MoveNext());
                Assert.False(strongBoxedEnumerator.MoveNext());

                Assert.True(weakBoxedEnumerator.MoveNext());
                Assert.Equal("name5", ((JsonProperty)weakBoxedEnumerator.Current).Name);
                Assert.Equal(5, ((JsonProperty)weakBoxedEnumerator.Current).Value.GetInt32());

                Assert.False(weakBoxedEnumerator.MoveNext());
                Assert.False(structEnumerator.MoveNext());
                Assert.False(strongBoxedEnumerator.MoveNext());
                Assert.False(weakBoxedEnumerator.MoveNext());
            }
        }

        [Fact]
        public static void DefaultObjectEnumeratorDoesNotThrow()
        {
            JsonElement.ObjectEnumerator enumerable = default;
            JsonElement.ObjectEnumerator enumerator = enumerable.GetEnumerator();
            JsonElement.ObjectEnumerator defaultEnumerator = default;

            Assert.Equal(JsonValueType.Undefined, enumerable.Current.Value.Type);
            Assert.Equal(JsonValueType.Undefined, enumerator.Current.Value.Type);

            Assert.Throws<InvalidOperationException>(() => enumerable.Current.Name);
            Assert.Throws<InvalidOperationException>(() => enumerator.Current.Name);

            Assert.False(enumerable.MoveNext());
            Assert.False(enumerable.MoveNext());
            Assert.False(defaultEnumerator.MoveNext());
        }

        [Fact]
        public static void ReadNestedObject()
        {
            const string json = @"
{
  ""first"":
  {
    ""true"": true,
    ""false"": false,
    ""null"": null,
    ""int"": 3,
    ""nearlyPi"": 3.14159,
    ""text"": ""This is some text that does not end... <EOT>""
  },
  ""second"":
  {
    ""blub"": { ""bool"": true },
    ""glub"": { ""bool"": false }
  }
}";
            using (JsonDocument doc = JsonDocument.Parse(json))
            {
                JsonElement root = doc.RootElement;
                Assert.Equal(JsonValueType.Object, root.Type);

                Assert.True(root.GetProperty("first").GetProperty("true").GetBoolean());
                Assert.False(root.GetProperty("first").GetProperty("false").GetBoolean());
                Assert.Equal(JsonValueType.Null, root.GetProperty("first").GetProperty("null").Type);
                Assert.Equal(3, root.GetProperty("first").GetProperty("int").GetInt32());
                Assert.Equal(3.14159f, root.GetProperty("first").GetProperty("nearlyPi").GetSingle());
                Assert.Equal("This is some text that does not end... <EOT>", root.GetProperty("first").GetProperty("text").GetString());

                Assert.True(root.GetProperty("second").GetProperty("blub").GetProperty("bool").GetBoolean());
                Assert.False(root.GetProperty("second").GetProperty("glub").GetProperty("bool").GetBoolean());
            }
        }

        private static ArraySegment<byte> StringToUtf8BufferWithEmptySpace(string testString, int emptySpaceSize = 2048)
        {
            int expectedLength = Encoding.UTF8.GetByteCount(testString);
            var buffer = new byte[expectedLength + emptySpaceSize];
            int actualLength = Encoding.UTF8.GetBytes(testString, buffer.AsSpan());
            
            return new ArraySegment<byte>(buffer, 0, actualLength);
        }

        private static ReadOnlySequence<byte> SegmentInto(ReadOnlyMemory<byte> data, int segmentCount)
        {
            if (segmentCount < 2)
                throw new ArgumentOutOfRangeException(nameof(segmentCount));

            int perSegment = data.Length / segmentCount;
            BufferSegment<byte> first;

            if (perSegment == 0 && data.Length > 0)
            {
                first = new BufferSegment<byte>(data.Slice(0, 1));
                data = data.Slice(1);
            }
            else
            {
                first = new BufferSegment<byte>(data.Slice(0, perSegment));
                data = data.Slice(perSegment);
            }

            BufferSegment<byte> last = first;
            segmentCount--;

            while (segmentCount > 1)
            {
                perSegment = data.Length / segmentCount;
                last = last.Append(data.Slice(0, perSegment));
                data = data.Slice(perSegment);
                segmentCount--;
            }

            last = last.Append(data);
            return new ReadOnlySequence<byte>(first, 0, last, data.Length);
        }
    }
}
