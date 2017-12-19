// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Test.Cryptography;

namespace System.Security.Cryptography.Pkcs.Tests
{
    internal sealed class TimestampTokenTestData
    {
        internal ReadOnlyMemory<byte> FullTokenBytes { get; }
        internal ReadOnlyMemory<byte> TokenInfoBytes { get; private set; }
        internal int Version => 1;
        internal string PolicyId { get; private set; }
        internal string HashAlgorithmId { get; private set; }
        internal ReadOnlyMemory<byte> HashBytes { get; private set; }
        internal ReadOnlyMemory<byte> SerialNumberBytes { get; private set; }
        internal bool TimestampTooPrecise { get; private set; }
        internal DateTimeOffset Timestamp { get; private set; }
        internal long? AccuracyInMicroseconds { get; private set; }
        internal bool IsOrdering { get; private set; }
        internal ReadOnlyMemory<byte>? NonceBytes { get; private set; }
        internal ReadOnlyMemory<byte>? TsaNameBytes { get; private set; }
        internal ReadOnlyMemory<byte>? ExtensionsBytes { get; private set; }

        private TimestampTokenTestData(string inputHex)
            : this(inputHex.HexToByteArray())
        {
        }

        private TimestampTokenTestData(ReadOnlyMemory<byte> fullTokenBytes)
        {
            FullTokenBytes = fullTokenBytes;
        }

        internal static readonly TimestampTokenTestData FreeTsaDotOrg1 = ((Func<TimestampTokenTestData>)(() =>
        {
            var data = new TimestampTokenTestData(
                "3082053606092A864886F70D010702A082052730820523020103310B30090605" +
                "2B0E03021A0500308201B1060B2A864886F70D0109100104A08201A00482019C" +
                "3082019802010106042A0304013041300D060960864801650304020205000430" +
                "9111E404B85D1F088C23DBE654943F30B103B6CBFE01898A1F7701A23B055E79" +
                "C27AEE38BC44CC0F212DBAC0EBE92C580203064F641816323031373132313831" +
                "37333431362E3830303831325A300A020101800201F48101640101FF02090096" +
                "31D170EA3B92D4A0820111A482010D308201093111300F060355040A13084672" +
                "656520545341310C300A060355040B130354534131763074060355040D136D54" +
                "686973206365727469666963617465206469676974616C6C79207369676E7320" +
                "646F63756D656E747320616E642074696D65207374616D702072657175657374" +
                "73206D616465207573696E672074686520667265657473612E6F7267206F6E6C" +
                "696E65207365727669636573311830160603550403130F7777772E6672656574" +
                "73612E6F72673122302006092A864886F70D0109011613627573696C657A6173" +
                "40676D61696C2E636F6D3112301006035504071309577565727A62757267310B" +
                "3009060355040613024445310F300D0603550408130642617965726E3182035A" +
                "308203560201013081A33081953111300F060355040A13084672656520545341" +
                "3110300E060355040B1307526F6F74204341311830160603550403130F777777" +
                "2E667265657473612E6F72673122302006092A864886F70D0109011613627573" +
                "696C657A617340676D61696C2E636F6D3112301006035504071309577565727A" +
                "62757267310F300D0603550408130642617965726E310B300906035504061302" +
                "4445020900C1E986160DA8E982300906052B0E03021A0500A0818C301A06092A" +
                "864886F70D010903310D060B2A864886F70D0109100104301C06092A864886F7" +
                "0D010905310F170D3137313231383137333431365A302306092A864886F70D01" +
                "090431160414F53C4FC877C8AE82F9695BFE039ED1F0D154D5D3302B060B2A86" +
                "4886F70D010910020C311C301A301830160414916DA3D860ECCA82E34BC59D17" +
                "93E7E968875F14300D06092A864886F70D01010105000482020078A64BC950D0" +
                "0A576DB1F1BBE822C08FA165689198CD19B4A64CB8E65CF3B33E69C7BA6EF4A3" +
                "A005F8138457063A331D293E822260AD4DDD8DE04D4161103CF5A554283E4B1C" +
                "7AAF57DA04E84FA3572A7F2DB1409C06B192C10C09A7672B0D45DDF114A5975C" +
                "388BEC9036FA1D557379B7B81D4B0329A599D98217EF2E7EEFD9439B29746A6E" +
                "93DB966072EE969B4468168E169DA035AD05A478A90475951EC27C8C32B0920B" +
                "735B15D32393B9271466B5F8217355B0F86B44DDE7F36CBBA2A90D4F285C15AE" +
                "17A8A1C8E536B5810B8219016009C0B8F8A2B893B662A4200BABF32E4CD21600" +
                "6B9132D75B9C7BFB85DE109C65F072E9A419548F2499631D04AD4ED83E420A51" +
                "64DEB505B3D345158FA936E8D559A860AEC5B5D79D1E7D7A02133868531CBFE7" +
                "84B32E4A4D74706E0A04161D97C5BA50D190ED8C2792EF1E8834E0982241D668" +
                "86B9CDACCFBE7CA890F71594818C50AA4EA66E21D539D108FE0A9116E18C421D" +
                "F544465469AD7F614BF79788E808B09A8C223A02F21D7CF1B1AB1D5210D74EAB" +
                "7958AD5035CA440BAC27C1CA9EAA603BBB4C85A09DBB4ADFA93FAF5262CFACC2" +
                "92C0513769CC02554A1315B40D16A9AE547E50F0AC4310D71F13D9E22ADFE241" +
                "D50DF295F1DB078C84EECBCB30F1018E939B1FEA8615B31F39F87F02EF816EFF" +
                "FE80A39C0857ECA510882DD2D66D49B743F0E7FF8DBEE4650449");

            data.TokenInfoBytes = data.FullTokenBytes.Slice(64, 412);
            data.PolicyId = "1.2.3.4.1";
            data.HashAlgorithmId = Oids.Sha384;
            data.HashBytes = data.TokenInfoBytes.Slice(32, 48);
            data.SerialNumberBytes = data.TokenInfoBytes.Slice(82, 3);
            data.Timestamp = new DateTimeOffset(2017, 12, 18, 17, 34, 16, TimeSpan.Zero);
            data.Timestamp += TimeSpan.FromTicks(8008120);
            data.TimestampTooPrecise = true;
            data.AccuracyInMicroseconds = 1 * 1000000L + 0x1F4 * 1000 + 0x64;
            data.IsOrdering = true;
            data.NonceBytes = data.TokenInfoBytes.Slice(126, 9);
            data.TsaNameBytes = data.TokenInfoBytes.Slice(139, 273);
            return data;
        }))();

        internal static readonly TimestampTokenTestData Symantec1 = ((Func<TimestampTokenTestData>)(() =>
        {
            var data = new TimestampTokenTestData(
                "30820E2406092A864886F70D010702A0820E1530820E11020103310D300B0609" +
                "6086480165030402013082010E060B2A864886F70D0109100104A081FE0481FB" +
                "3081F8020101060B6086480186F845010717033031300D060960864801650304" +
                "020105000420315F5BDB76D078C43B8AC0064E4A0164612B1FCE77C869345BFC" +
                "94C75894EDD302146C77B12D5FCF9F6DC1D4A481E935F446FBA376C4180F3230" +
                "3137313031303232303835325A300302011EA08186A48183308180310B300906" +
                "0355040613025553311D301B060355040A131453796D616E74656320436F7270" +
                "6F726174696F6E311F301D060355040B131653796D616E746563205472757374" +
                "204E6574776F726B3131302F0603550403132853796D616E7465632053484132" +
                "35362054696D655374616D70696E67205369676E6572202D204732A0820A8B30" +
                "82053830820420A00302010202107B05B1D449685144F7C989D29C199D12300D" +
                "06092A864886F70D01010B05003081BD310B3009060355040613025553311730" +
                "15060355040A130E566572695369676E2C20496E632E311F301D060355040B13" +
                "16566572695369676E205472757374204E6574776F726B313A3038060355040B" +
                "1331286329203230303820566572695369676E2C20496E632E202D20466F7220" +
                "617574686F72697A656420757365206F6E6C79313830360603550403132F5665" +
                "72695369676E20556E6976657273616C20526F6F742043657274696669636174" +
                "696F6E20417574686F72697479301E170D3136303131323030303030305A170D" +
                "3331303131313233353935395A3077310B3009060355040613025553311D301B" +
                "060355040A131453796D616E74656320436F72706F726174696F6E311F301D06" +
                "0355040B131653796D616E746563205472757374204E6574776F726B31283026" +
                "0603550403131F53796D616E746563205348413235362054696D655374616D70" +
                "696E6720434130820122300D06092A864886F70D01010105000382010F003082" +
                "010A0282010100BB599D59554F9D8C725D1A81A2EB55F3B001AD3C71AC328F05" +
                "6B869A270032976A4DC964144B29BBC2D929B92EEC63B3E1CF3F0B5690F8621B" +
                "7EEBA607E2DE7F5E6D4038D49106E7417C791CCBCBAD1BBFD89591F3F0EE6CF8" +
                "AD96392E7FC127B87839C584A5EDEDAF878ECE8DC76DEAD298B53A1F1E399DC3" +
                "F49AA8F484E1C4D17C71C60629B43FE4830D26C37B083E4DF90AB73349FFCA3B" +
                "D4F5B29B4BE188991AF5C0E93314D6DFC780DB91EEFEBC92577277F4CDA8CCFE" +
                "09F59337BE95886AC5DCF4B14BD4CEE809915FB58479358A78AC19328F23C132" +
                "411B590EA93EB1CCF9D62BEFB7D8E4D51D6D113A92F693C99CE348EEBB530ED4" +
                "36978678C5A1370203010001A382017730820173300E0603551D0F0101FF0404" +
                "0302010630120603551D130101FF040830060101FF02010030660603551D2004" +
                "5F305D305B060B6086480186F84501071703304C302306082B06010505070201" +
                "161768747470733A2F2F642E73796D63622E636F6D2F637073302506082B0601" +
                "050507020230191A1768747470733A2F2F642E73796D63622E636F6D2F727061" +
                "302E06082B0601050507010104223020301E06082B0601050507300186126874" +
                "74703A2F2F732E73796D63642E636F6D30360603551D1F042F302D302BA029A0" +
                "278625687474703A2F2F732E73796D63622E636F6D2F756E6976657273616C2D" +
                "726F6F742E63726C30130603551D25040C300A06082B06010505070308302806" +
                "03551D110421301FA41D301B311930170603550403131054696D655374616D70" +
                "2D323034382D33301D0603551D0E04160414AF63D6CAA34E8572E0A7BC41F329" +
                "A2387F807562301F0603551D23041830168014B677FA6948479F5312D5C2EA07" +
                "327607D1970719300D06092A864886F70D01010B0500038201010075EAB02DD5" +
                "34195C3245FE0EE1D44FA678C16FD7EADDDC4FF3A1C88188F7A78F15E64029AD" +
                "E65DF4A2D956648471302ADD1E61176620560698198D5D71F2F897BC09FD1C91" +
                "47C9E2E88D03FBCC902FD60A6C4E33ECD6B493C84C906348394021C4DDD66E89" +
                "983CB59897E8A906B709C98F535741902FE11E4D4EDCCA10786C426EF0B6C5F8" +
                "615C52F54EF66B8DF74A7ABEF3CDFD03D7D9F603A80FE353F70A75ECC6752EAA" +
                "66850499B7F80657E1C60EF6E8AFDAEC9B181FAAB9E33A00BFCE8A94CB01DB9E" +
                "C738BB0F52ABD1E39403600A4DA0FE276D1432FC3F9740E1BF9989DBE43914BD" +
                "DAE4D3C3EA2B5AB3955855047DC79AEC23038D852AD2FFAEA961813082054B30" +
                "820433A00302010202105458F2AAD741D644BC84A97BA09652E6300D06092A86" +
                "4886F70D01010B05003077310B3009060355040613025553311D301B06035504" +
                "0A131453796D616E74656320436F72706F726174696F6E311F301D060355040B" +
                "131653796D616E746563205472757374204E6574776F726B3128302606035504" +
                "03131F53796D616E746563205348413235362054696D655374616D70696E6720" +
                "4341301E170D3137303130323030303030305A170D3238303430313233353935" +
                "395A308180310B3009060355040613025553311D301B060355040A131453796D" +
                "616E74656320436F72706F726174696F6E311F301D060355040B131653796D61" +
                "6E746563205472757374204E6574776F726B3131302F0603550403132853796D" +
                "616E746563205348413235362054696D655374616D70696E67205369676E6572" +
                "202D20473230820122300D06092A864886F70D01010105000382010F00308201" +
                "0A028201010099F3FCD804090386F9D75CA693C0427CEA7C63CF5D00E28EF3C0" +
                "90DF8F29F518EA94B792E5D7B0A07381E8E90A9B4A7C01FF9D8FA439A70EEA45" +
                "F4220C3A70ED39458BE4C51B5CF0456846240563769B1CFC9E6C2AB156E58A7F" +
                "5271AEF235D54623061CCF482D1DB4CDB8D976238E1CFF3EBFBB065C6907A665" +
                "0EF85EAE7D2EED4DAE35EFC9D70042FD28950E9F5D724209BCC3DA44D2EDCC47" +
                "84E4FCCA2DAC58BEAEF7AED9440D08B7C277D61A4370D16E03DE5292C4100871" +
                "D9BA2255F21FBCED9B9D3BE25E1D4C83FF970F7B0BE755834ED20DEBBED7ECAE" +
                "6E47B99FDFA5D651BC0455EDFF27704CC9ED2A4B13E1B1B94C0FC901EE55655F" +
                "69027866CB3F0203010001A38201C7308201C3300C0603551D130101FF040230" +
                "0030660603551D20045F305D305B060B6086480186F84501071703304C302306" +
                "082B06010505070201161768747470733A2F2F642E73796D63622E636F6D2F63" +
                "7073302506082B0601050507020230191A1768747470733A2F2F642E73796D63" +
                "622E636F6D2F72706130400603551D1F043930373035A033A031862F68747470" +
                "3A2F2F74732D63726C2E77732E73796D616E7465632E636F6D2F736861323536" +
                "2D7473732D63612E63726C30160603551D250101FF040C300A06082B06010505" +
                "070308300E0603551D0F0101FF040403020780307706082B0601050507010104" +
                "6B3069302A06082B06010505073001861E687474703A2F2F74732D6F6373702E" +
                "77732E73796D616E7465632E636F6D303B06082B06010505073002862F687474" +
                "703A2F2F74732D6169612E77732E73796D616E7465632E636F6D2F7368613235" +
                "362D7473732D63612E63657230280603551D110421301FA41D301B3119301706" +
                "03550403131054696D655374616D702D323034382D35301D0603551D0E041604" +
                "1409B5C1FE96729729439AC9E002BAAEF8FD2FBAF6301F0603551D2304183016" +
                "8014AF63D6CAA34E8572E0A7BC41F329A2387F807562300D06092A864886F70D" +
                "01010B0500038201010017B30A88E95C5A5E206B3B0A15B26CC5A98A3287D3B1" +
                "F41C53AE85BE3F9BFFD7BCB79485B4C7527E94E8BDED61B2D4A799E4C3C993C1" +
                "353D0BE8680A5D5698BDB1223BD1447AD7BFF06D51328AD523DF380137F6E253" +
                "2B7A2B118FB74D6C7A33031B7C6B099417BBE4DB58D4211365E7ECD125CA2C75" +
                "9A9C7FFCC9BB2A68ABC47DB4CFA3C96CA7D9C4009C890A7791F44DA2FB313B86" +
                "6EF6E61F5003869BBFCB42ABE6769B725A11018AC6EFA56F95E7DDAEBAE62265" +
                "F018591B11C9CD80B7D897471F4208F8AC711FB04653B3D4B2D5A3AB50754812" +
                "1782ADCFE0414F327ECD951CBF918A083DA4A7670296DF244CA5D041C08260A3" +
                "8A17324BD3BCCFA4B48C3182025A3082025602010130818B3077310B30090603" +
                "55040613025553311D301B060355040A131453796D616E74656320436F72706F" +
                "726174696F6E311F301D060355040B131653796D616E74656320547275737420" +
                "4E6574776F726B312830260603550403131F53796D616E746563205348413235" +
                "362054696D655374616D70696E6720434102105458F2AAD741D644BC84A97BA0" +
                "9652E6300B0609608648016503040201A081A4301A06092A864886F70D010903" +
                "310D060B2A864886F70D0109100104301C06092A864886F70D010905310F170D" +
                "3137313031303232303835325A302F06092A864886F70D01090431220420B50E" +
                "D0D890F9195926E4D7D2ACC301FB7C33460AF36509BFBE3C692C3BA5EC3B3037" +
                "060B2A864886F70D010910022F31283026302430220420CF7AC17AD047ECD5FD" +
                "C36822031B12D4EF078B6F2B4C5E6BA41F8FF2CF4BAD67300B06092A864886F7" +
                "0D010101048201003368AF4246A64CD0C2FC5CF85A05E923CC64A5DA51CEB9A5" +
                "46C7ADB1230F1E13A87934C7A857B8B6565AD17CE4C09914F95949DBB34C9F1B" +
                "25FBDAA9AD777698FA3400708C8BE678B49F19CE222F86A14A00DBC706972119" +
                "FD93DC6971F9390A826FB1953498569FD646A58C99C46C8A2683378819D4C54E" +
                "F21EB9846AA69D985DCC68D9FAFDDA365B50D8CBAD7B8865AD58A5B7CD85CC66" +
                "B2733193C5674971BAC64EDADCA8880944572CBF4D5DD0D22B6BB0421C537885" +
                "0E8F60BAD98EB85C7B09EBBCE11A759181EA9C32A83C8D1B73E54F3A571D1461" +
                "FD6B6AB4F89DC6750F14EC2E0134BA61B4D0B2C1FB2F60F622379249CE6381AF" +
                "667900B17A7BB6AF");

            data.TokenInfoBytes = data.FullTokenBytes.Slice(64, 251);
            data.PolicyId = "2.16.840.1.113733.1.7.23.3";
            data.HashAlgorithmId = Oids.Sha256;
            data.HashBytes = data.TokenInfoBytes.Slice(38, 32);
            data.SerialNumberBytes = data.TokenInfoBytes.Slice(72, 20);
            data.Timestamp = new DateTimeOffset(2017, 10, 10, 22, 8, 52, TimeSpan.Zero);
            data.AccuracyInMicroseconds = 30 * 1000000L;
            data.IsOrdering = false;
            data.TsaNameBytes = data.TokenInfoBytes.Slice(117, 134);
            return data;
        }))();
    }
}
