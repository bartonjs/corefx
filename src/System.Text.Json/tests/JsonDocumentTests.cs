// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

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
            string message = obj["message"].GetString();
            return message;
        }

        private static string ReadJson400KB(JsonElement obj)
        {
            var sb = new StringBuilder();
            int length = obj.GetArrayLength();
            for (int i = 0; i < length; i++)
            {
                sb.Append(obj[i]["_id"].GetString());
                sb.Append(obj[i]["index"].GetInt32());
                sb.Append(obj[i]["guid"].GetString());
                sb.Append(obj[i]["isActive"].GetBoolean());
                sb.Append(obj[i]["balance"].GetString());
                sb.Append(obj[i]["picture"].GetString());
                sb.Append(obj[i]["age"].GetInt32());
                sb.Append(obj[i]["eyeColor"].GetString());
                sb.Append(obj[i]["name"].GetString());
                sb.Append(obj[i]["gender"].GetString());
                sb.Append(obj[i]["company"].GetString());
                sb.Append(obj[i]["email"].GetString());
                sb.Append(obj[i]["phone"].GetString());
                sb.Append(obj[i]["address"].GetString());
                sb.Append(obj[i]["about"].GetString());
                sb.Append(obj[i]["registered"].GetString());
                sb.Append(obj[i]["latitude"].GetDouble());
                sb.Append(obj[i]["longitude"].GetDouble());

                JsonElement tags = obj[i]["tags"];
                for (int j = 0; j < tags.GetArrayLength(); j++)
                {
                    sb.Append(tags[j].GetString());
                }
                JsonElement friends = obj[i]["friends"];
                for (int j = 0; j < friends.GetArrayLength(); j++)
                {
                    sb.Append(friends[j]["id"].GetInt32());
                    sb.Append(friends[j]["name"].GetString());
                }
                sb.Append(obj[i]["greeting"].GetString());
                sb.Append(obj[i]["favoriteFruit"].GetString());
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
            JsonTokenType type = element.Type;

            switch (type)
            {
                case JsonTokenType.False:
                case JsonTokenType.True:
                case JsonTokenType.String:
                case JsonTokenType.Number:
                {
                    buf.Append(element.ToString());
                    buf.Append(", ");
                    break;
                }
                case JsonTokenType.StartObject:
                {
                    foreach (JsonProperty prop in element.EnumerateObject())
                    {
                        buf.Append(prop.Name);
                        buf.Append(", ");
                        DepthFirstAppend(buf, prop.Value);
                    }

                    break;
                }
                case JsonTokenType.StartArray:
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

                int age = parsedObject["age"].GetInt32();
                string ageString = parsedObject["age"].ToString();
                string first = parsedObject["first"].GetString();
                string last = parsedObject["last"].GetString();
                string phoneNumber = parsedObject["phoneNumber"].GetString();
                string street = parsedObject["street"].GetString();
                string city = parsedObject["city"].GetString();
                int zip = parsedObject["zip"].GetInt32();

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
                double age = person["age"].GetDouble();
                string first = person["first"].GetString();
                string last = person["last"].GetString();
                JsonElement phoneNums = person["phoneNumbers"];
                Assert.Equal(2, phoneNums.GetArrayLength());
                string phoneNum1 = phoneNums[0].GetString();
                string phoneNum2 = phoneNums[1].GetString();
                JsonElement address = person["address"];
                string street = address["street"].GetString();
                string city = address["city"].GetString();
                double zipCode = address["zip"].GetDouble();

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
                Assert.Throws<InvalidOperationException>(() => phoneNums["2"]);
                Assert.Throws<KeyNotFoundException>(() => address["2"]);
                Assert.Throws<InvalidOperationException>(() => address["city"].GetDouble());
                Assert.Throws<InvalidOperationException>(() => address["city"].GetBoolean());
                Assert.Throws<InvalidOperationException>(() => address["zip"].GetString());
                Assert.Throws<InvalidOperationException>(() => person["phoneNumbers"].GetString());
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

                Assert.Equal(JsonTokenType.StartArray, root.Type);
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

                Assert.Equal(JsonTokenType.StartObject, root.Type);
                Assert.Equal(SR.BasicJson, root.ToString());
            }
        }

        [Theory]
        [InlineData(0)]
        [InlineData(int.MaxValue)]
        [InlineData(int.MinValue)]
        public static void ReadSmallInteger(int value)
        {
            double expectedDouble = value;
            ArraySegment<byte> buffer = StringToUtf8BufferWithEmptySpace("    " + value + "  ", 0);

            using (JsonDocument doc = JsonDocument.Parse(buffer, default))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonTokenType.Number, root.Type);
                
                Assert.True(root.TryGetDouble(out double doubleVal));
                Assert.Equal(expectedDouble, doubleVal);

                Assert.True(root.TryGetInt32(out int intVal));
                Assert.Equal(value, intVal);

                Assert.True(root.TryGetInt64(out long longVal));
                Assert.Equal(value, longVal);

                Assert.Equal(expectedDouble, root.GetDouble());
                Assert.Equal(value, root.GetInt32());
                Assert.Equal(value, root.GetInt64());

                if (value >= 0)
                {
                    ulong expectedULong = (ulong)value;
                    Assert.True(root.TryGetUInt64(out ulong ulongVal));
                    Assert.Equal(expectedULong, ulongVal);

                    Assert.Equal(expectedULong, root.GetUInt64());
                }
                else
                {
                    Assert.False(root.TryGetUInt64(out ulong ulongValue));
                    Assert.Equal(0UL, ulongValue);

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

            using (JsonDocument doc = JsonDocument.Parse("    " + value + "  ", default))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonTokenType.Number, root.Type);

                Assert.True(root.TryGetDouble(out double doubleVal));
                Assert.Equal(expectedDouble, doubleVal);

                Assert.False(root.TryGetInt32(out int intVal));
                Assert.Equal(0, intVal);

                Assert.True(root.TryGetInt64(out long longVal));
                Assert.Equal(value, longVal);

                Assert.Equal(expectedDouble, root.GetDouble());
                Assert.Throws<FormatException>(() => root.GetInt32());
                Assert.Equal(value, root.GetInt64());

                if (value >= 0)
                {
                    ulong expectedULong = (ulong)value;
                    Assert.True(root.TryGetUInt64(out ulong ulongVal));
                    Assert.Equal(expectedULong, ulongVal);

                    Assert.Equal(expectedULong, root.GetUInt64());
                }
                else
                {
                    Assert.False(root.TryGetUInt64(out ulong ulongValue));
                    Assert.Equal(0UL, ulongValue);

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

            using (JsonDocument doc = JsonDocument.Parse("    " + value + "  ", default))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonTokenType.Number, root.Type);

                Assert.True(root.TryGetDouble(out double doubleVal));
                Assert.Equal(expectedDouble, doubleVal);

                Assert.False(root.TryGetInt32(out int intVal));
                Assert.Equal(0, intVal);

                Assert.False(root.TryGetInt64(out long longVal));
                Assert.Equal(0L, longVal);

                Assert.Equal(expectedDouble, root.GetDouble());
                Assert.Throws<FormatException>(() => root.GetInt32());
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
            double expectedDouble = ulong.MaxValue;
            expectedDouble *= 10;

            using (JsonDocument doc = JsonDocument.Parse("    " + ulong.MaxValue + "0  ", default))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonTokenType.Number, root.Type);

                Assert.True(root.TryGetDouble(out double doubleVal));
                Assert.Equal(expectedDouble, doubleVal);

                Assert.False(root.TryGetInt32(out int intVal));
                Assert.Equal(0, intVal);

                Assert.False(root.TryGetInt64(out long longVal));
                Assert.Equal(0L, longVal);

                Assert.False(root.TryGetUInt64(out ulong ulongVal));
                Assert.Equal(0UL, ulongVal);

                Assert.Equal(expectedDouble, root.GetDouble());
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

        [Theory]
        [InlineData("1e+1", 10)]
        [InlineData("1.1e-0", 1.1)]
        [InlineData("3.14159", 3.14159)]
        [InlineData("1e-10", 1e-10)]
        public static void ReadNonInteger(string str, double val)
        {
            using (JsonDocument doc = JsonDocument.Parse("    " + str + "  ", default))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonTokenType.Number, root.Type);

                Assert.True(root.TryGetDouble(out double doubleVal));
                Assert.Equal(val, doubleVal);

                Assert.False(root.TryGetInt32(out int intVal));
                Assert.Equal(0, intVal);

                Assert.False(root.TryGetInt64(out long longVal));
                Assert.Equal(0L, longVal);

                Assert.False(root.TryGetUInt64(out ulong ulongVal));
                Assert.Equal(0UL, ulongVal);

                Assert.Equal(val, root.GetDouble());
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
            using (JsonDocument doc = JsonDocument.Parse("    1e+100000002", default))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(JsonTokenType.Number, root.Type);

                Assert.True(root.TryGetDouble(out double doubleVal));
                Assert.Equal(double.PositiveInfinity, doubleVal);

                Assert.False(root.TryGetInt32(out int intVal));
                Assert.Equal(0, intVal);

                Assert.False(root.TryGetInt64(out long longVal));
                Assert.Equal(0L, longVal);

                Assert.False(root.TryGetUInt64(out ulong ulongVal));
                Assert.Equal(0UL, ulongVal);

                Assert.Equal(double.PositiveInfinity, root.GetDouble());
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

                Assert.Equal(JsonTokenType.StartArray, root.Type);
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

            Assert.Equal(JsonTokenType.None, root.Type);

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

        private static ArraySegment<byte> StringToUtf8BufferWithEmptySpace(string testString, int emptySpaceSize = 2048)
        {
            int expectedLength = Encoding.UTF8.GetByteCount(testString);
            var buffer = new byte[expectedLength + emptySpaceSize];
            int actualLength = Encoding.UTF8.GetBytes(testString, buffer.AsSpan());
            
            return new ArraySegment<byte>(buffer, 0, actualLength);
        }
    }
}
