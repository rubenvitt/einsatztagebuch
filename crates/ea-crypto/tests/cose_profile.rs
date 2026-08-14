use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, CoseSigner, ProtectedHeader, SecretBytes,
    UnverifiedRfc3161TimeStampToken, attach_rfc3161_ctt, cose_sign1_ctt_imprint,
    encode_signed_protocol_wrapper, parse_cose_sign1, validate_unsigned_protocol_core,
    verify_enrollment_pop, verify_initial_root_pop,
};
use ea_types::CertificateHash;

const NORMAL_PROTECTED_HEX: &str = "a50132028303046f63657274696669636174654861736803782b6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e7265636f72642d646967657374045820be5de2f4bcdc383add3fc9827d345f1a37c6a06026b38696fb3229c003b35f496f6365727469666963617465486173685820d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef";
const INITIAL_ROOT_PROTECTED_HEX: &str = "a401320282030403782a6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e74727573742d646967657374045820be5de2f4bcdc383add3fc9827d345f1a37c6a06026b38696fb3229c003b35f49";
const ENROLLMENT_PROTECTED_HEX: &str = "a401320282030403783e6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e6465766963652d726567697374726174696f6e2d726571756573742b63626f72045820be5de2f4bcdc383add3fc9827d345f1a37c6a06026b38696fb3229c003b35f49";
const CHALLENGE_CORE_HEX: &str = "870150000102030405060708090a0b0c0d0e0f5820202020202020202020202020202020202020202020202020202020202020202018183903e75820303030303030303030303030303030303030303030303030303030303030303080";
const CHALLENGE_COSE_HEX: &str = "d28458a4a50132028303046f6365727469666963617465486173680378356170706c69636174696f6e2f766e642e65696e7361747a6172636869762e6368616c6c656e67652d726573706f6e73652b63626f72045820be5de2f4bcdc383add3fc9827d345f1a37c6a06026b38696fb3229c003b35f496f63657274696669636174654861736858203030303030303030303030303030303030303030303030303030303030303030a0585d870150000102030405060708090a0b0c0d0e0f5820202020202020202020202020202020202020202020202020202020202020202018183903e7582030303030303030303030303030303030303030303030303030303030303030308058404d7fe09caac8745e1a8873c1a84b9285e88352aa9adb08e64ff8cb640113f2092286b46c8a4c23b5d8b3d03723bb2c7902b38ca038386abf3602c1d185e26f01";
const CHALLENGE_WRAPPER_HEX: &str = "82870150000102030405060708090a0b0c0d0e0f5820202020202020202020202020202020202020202020202020202020202020202018183903e75820303030303030303030303030303030303030303030303030303030303030303080d28458a4a50132028303046f6365727469666963617465486173680378356170706c69636174696f6e2f766e642e65696e7361747a6172636869762e6368616c6c656e67652d726573706f6e73652b63626f72045820be5de2f4bcdc383add3fc9827d345f1a37c6a06026b38696fb3229c003b35f496f63657274696669636174654861736858203030303030303030303030303030303030303030303030303030303030303030a0585d870150000102030405060708090a0b0c0d0e0f5820202020202020202020202020202020202020202020202020202020202020202018183903e7582030303030303030303030303030303030303030303030303030303030303030308058404d7fe09caac8745e1a8873c1a84b9285e88352aa9adb08e64ff8cb640113f2092286b46c8a4c23b5d8b3d03723bb2c7902b38ca038386abf3602c1d185e26f01";
const REGISTRATION_CORE_HEX: &str = "890150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f005828a30101200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8f68101817545494e5341545a4152434849562d53554954452d3180";
const REGISTRATION_COSE_HEX: &str = "d284586ba401320282030403783e6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e6465766963652d726567697374726174696f6e2d726571756573742b63626f72045820be5de2f4bcdc383add3fc9827d345f1a37c6a06026b38696fb3229c003b35f49a0586a890150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f005828a30101200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8f68101817545494e5341545a4152434849562d53554954452d318058403662bd657ced23c55282bcae6640b6cbff85640831ca36795d170a859fbc97c1bb77832f882f4ec0b314f2c3e1a2b87d3dc3cfe0bd2addd1ffea8fa559c8b403";
const REGISTRATION_WRAPPER_HEX: &str = "82890150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f005828a30101200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8f68101817545494e5341545a4152434849562d53554954452d3180d284586ba401320282030403783e6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e6465766963652d726567697374726174696f6e2d726571756573742b63626f72045820be5de2f4bcdc383add3fc9827d345f1a37c6a06026b38696fb3229c003b35f49a0586a890150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f005828a30101200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8f68101817545494e5341545a4152434849562d53554954452d318058403662bd657ced23c55282bcae6640b6cbff85640831ca36795d170a859fbc97c1bb77832f882f4ec0b314f2c3e1a2b87d3dc3cfe0bd2addd1ffea8fa559c8b403";
const READER_ACK_CORE_HEX: &str = "880150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f582040404040404040404040404040404040404040404040404040404040404040401818582050505050505050505050505050505050505050505050505050505050505050503903e780";
const READER_ACK_COSE_HEX: &str = "d284589ca50132028303046f63657274696669636174654861736803782d6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e7265616465722d61636b2b63626f72045820be5de2f4bcdc383add3fc9827d345f1a37c6a06026b38696fb3229c003b35f496f63657274696669636174654861736858204040404040404040404040404040404040404040404040404040404040404040a0586e880150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f582040404040404040404040404040404040404040404040404040404040404040401818582050505050505050505050505050505050505050505050505050505050505050503903e78058403cfaa58bd399a5ec852f2cf12d9dfd369e7dfd410437db43028b96aa035d615211047437c1a847e0c09b5b0ceb76646aa2573ce9924f06e7f01dce609e3a0b0f";
const READER_ACK_WRAPPER_HEX: &str = "82880150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f582040404040404040404040404040404040404040404040404040404040404040401818582050505050505050505050505050505050505050505050505050505050505050503903e780d284589ca50132028303046f63657274696669636174654861736803782d6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e7265616465722d61636b2b63626f72045820be5de2f4bcdc383add3fc9827d345f1a37c6a06026b38696fb3229c003b35f496f63657274696669636174654861736858204040404040404040404040404040404040404040404040404040404040404040a0586e880150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f582040404040404040404040404040404040404040404040404040404040404040401818582050505050505050505050505050505050505050505050505050505050505050503903e78058403cfaa58bd399a5ec852f2cf12d9dfd369e7dfd410437db43028b96aa035d615211047437c1a847e0c09b5b0ceb76646aa2573ce9924f06e7f01dce609e3a0b0f";
const CHECKPOINT_CORE_HEX: &str = "8b01781b45494e5341545a4152434849562d434845434b504f494e542d763150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f1718185820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f5820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f1903e7f680";
const RENEWAL_CORE_HEX: &str = "8801782145494e5341545a4152434849562d45564944454e43452d52454e4557414c2d763150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f5820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3ff6825820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f5820606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80";
const LOCAL_AUDIT_CORE_HEX: &str = "8c0150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f50202122232425262728292a2b2c2d2e2ff65820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00011903e78200f65820606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80";
const RFC9921_TOKEN_HEX: &str = concat!(
    "3082154906092a864886f70d010702a082153a30821536020103310f300d0609608648016503040203050030820184060b2a864886f70d01",
    "09100104a08201730482016f3082016b02010106042a0304013031300d060960864801650304020105000420dd9471efe743c4051335df8f",
    "6d2882f3badc387700f7ed3f7091672a3eeaf7c8020400b8a1ea180f32303235303832393037353330305a0101ffa0820111a482010d3082",
    "01093111300f060355040a13084672656520545341310c300a060355040b130354534131763074060355040d136d54686973206365727469",
    "666963617465206469676974616c6c79207369676e7320646f63756d656e747320616e642074696d65207374616d70207265717565737473",
    "206d616465207573696e672074686520667265657473612e6f7267206f6e6c696e65207365727669636573311830160603550403130f7777",
    "772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d31123010060355",
    "04071309577565727a62757267310b3009060355040613024445310f300d0603550408130642617965726ea082100830820801308205e9a0",
    "03020102020900c1e986160da8e982300d06092a864886f70d01010d05003081953111300f060355040a130846726565205453413110300e",
    "060355040b1307526f6f74204341311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d01090116",
    "13627573696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310f300d060355040813064261796572",
    "6e310b3009060355040613024445301e170d3136303331333031353733395a170d3236303331313031353733395a308201093111300f0603",
    "55040a13084672656520545341310c300a060355040b130354534131763074060355040d136d546869732063657274696669636174652064",
    "69676974616c6c79207369676e7320646f63756d656e747320616e642074696d65207374616d70207265717565737473206d616465207573",
    "696e672074686520667265657473612e6f7267206f6e6c696e65207365727669636573311830160603550403130f7777772e667265657473",
    "612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d311230100603550407130957756572",
    "7a62757267310b3009060355040613024445310f300d0603550408130642617965726e30820222300d06092a864886f70d01010105000382",
    "020f003082020a0282020100b591048c4e486f34e9dc08627fc2375162236984b82cb130beff517cfc38f84bce5c65a874dab2621ae0bce7",
    "e33563e0ede934fd5f8823159f07848808227460c1ed88261706f4281334359dfbb81bd1353fc179610af1a8c8c865dc00ea23b3a89be6bd",
    "03ba85a9ec827d60565905e22d6a584ed1380ae150280cee397e98a012f380464007862443bc077cb95f421af31712d9683cdb6dffbaf3c8",
    "ba5ba566ae523d459d6177346d4d840e27886b7c01c5b890d78a2e27bba8dd2f9a2812e157d62f921c65962548069dcdb7d06de181de0e95",
    "70d66f87220ce28b628ab55906f3ee0c210f7051e8f4858af8b9a92d09e46af2d9cba5bfcfad168cdf604491a4b06603b114caf7031f065e",
    "7eeefa53c575f3490c059d2e32ddc76ac4d4c4c710683b97fd1be591bc61055186d88f9a0391b307b6f91ed954daa36f9acd6a1e14aa2e4a",
    "df17464b54db18dbb6ffe30080246547370436ce4e77bae5de6fe0f3f9d6e7ffbeb461e794e92fb0951f8aae61a412cce9b21074635c8be3",
    "27ae1a0f6b4a646eb0f8463bc63bf845530435d19e802511ec9f66c3496952d8becb69b0aa4d4c41f60515fe7dcbb89319cdda59ba6aea4b",
    "e3ceae718e6fcb6ccd7db9fc50bb15b12f3665b0aa307289c2e6dd4b111ce48ba2d9efdb5a6b9a506069334fb34f6fc7ae330f0b34208aac",
    "80df3266fdd90465876ba2cb898d9505315b6e7b0203010001a38201db308201d730090603551d1304023000301d0603551d0e041604146e",
    "760b7b4e4f9ce160ca6d2ce927a2a294b37737301f0603551d23041830168014fa550d8c346651434cf7e7b3a76c95af7ae6a497300b0603",
    "551d0f0404030206c030160603551d250101ff040c300a06082b06010505070308306306082b0601050507010104573055302a06082b0601",
    "0505073002861e687474703a2f2f7777772e667265657473612e6f72672f7473612e637274302706082b06010505073001861b687474703a",
    "2f2f7777772e667265657473612e6f72673a3235363030370603551d1f0430302e302ca02aa0288626687474703a2f2f7777772e66726565",
    "7473612e6f72672f63726c2f726f6f745f63612e63726c3081c60603551d200481be3081bb3081b80601003081b2303306082b0601050507",
    "02011627687474703a2f2f7777772e667265657473612e6f72672f667265657473615f6370732e68746d6c303206082b0601050507020116",
    "26687474703a2f2f7777772e667265657473612e6f72672f667265657473615f6370732e706466304706082b06010505070202303b1a3946",
    "72656554534120747275737465642074696d657374616d70696e6720536f6674776172652061732061205365727669636520285361615329",
    "300d06092a864886f70d01010d05000382020100a5c944e2c6fac0a14d930a7fd0a0b172b41fc1483c3e957c68a2bcd9b9764f1a950161fd",
    "72472d41a5eed277786203b5422240fb3a26cde176087b6fb1011df4cc19e2571aa4a051109665e94c46f50bd2adee6ac4137e251b25a39d",
    "abda451515d8ff9e07209e8ec20b7874f7e1a0ede7c00937fe84a334f8b3265ced2d8ed9df61396583677feb382c1ee3b23e6ea5f05df30d",
    "e7b9f89005d25266f612f39c8b4f6daba6d7bfbac19632b90637329f52a6f066a10e43eaa81f849a6c5fe3fe8b5ea23275f687f2052e502e",
    "a6c30762a668cce07871dd8e97e315bba929e25589977a0a312ce96c5106b1437c779f2b361b182888f3ee8a234374fa063e956192627f7c",
    "431073965d1260928eba009e803429ae324cf96f042354f37bca5afddc79f79346ab388bfc79f01dc9861254ea6cc129941076b83d20556f",
    "3be51326837f2876f7833b370e7c3d410523827d4f53400c72218d75229ff10c6f8893a9a3a1c0c42bb4c898c13df41c7f6573b4fc565159",
    "71a610a7b0d2857c8225a9fb204eaceca2e8971aa1af87886a2ae3c72fe0a0aae842980a77bef16b92115458090d982b5946603764e75a0a",
    "d3d11454b9986f678b9ab6afe8497033ae3abfd4eb43b7bc9dee68815949e6481582a82e785277f2282107efe390200e0508acb8ea82ea25",
    "05276f3c9da2a3d3b4ad38bbf8842bda36fc2448291f558dc02dd1e0308207ff308205e7a003020102020900c1e986160da8e980300d0609",
    "2a864886f70d01010d05003081953111300f060355040a130846726565205453413110300e060355040b1307526f6f742043413118301606",
    "03550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f",
    "6d3112301006035504071309577565727a62757267310f300d0603550408130642617965726e310b3009060355040613024445301e170d31",
    "36303331333031353231335a170d3431303330373031353231335a3081953111300f060355040a130846726565205453413110300e060355",
    "040b1307526f6f74204341311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d01090116136275",
    "73696c657a617340676d61696c2e636f6d3112301006035504071309577565727a62757267310f300d0603550408130642617965726e310b",
    "300906035504061302444530820222300d06092a864886f70d01010105000382020f003082020a0282020100b6028e0e3032f11110d964cd",
    "a94b9d0278e1942ae913aaa59907cda69793995bd9ac7e33bad9fe3704da1c01a98d21afe3f591a59d7067705167998f5016722e0ab462b2",
    "1f439171d2cfcc4593f3735af794a5ab311f6c010c7898de33d75c4510ee76f4bd1d1498cf17d303f06a5dd9f796cc6ca9b657a56fe3ea4f",
    "efbe7ce6b6a18d3e35a30cee5ff170d1cf39a333d3fda8964d22db685b29e561be890f0aa845873b2e84ab26ab839ffe8fade9d23bb31e61",
    "d273cc9b880649185fabecfa0534600aba901b614e2e854582dea2226fc19cd7df52bed50d8777cd9988c053a3fc7dc3287a068a4ff12b71",
    "3cd9803666e955385456ff38f80298cf6b93856e9224774a66cf1cdd11c2f8efd85203d7458b25664b13ed639cded4ff8113d6cc5353d272",
    "9473c3c307157c722aa5b5dd0bfb2d6c38b1b93749c881ec60026d08951b3824bd71bacbce473aebd636f0b918b4a2c8ff4694f07457af2d",
    "6f1cf82554d1770fd79ff5d314dcd104cddcabc94138056dfcf017e7eb8572fd52f70144f188da05f5823f58dd06297e7387bed2d772c13d",
    "a8266601045fe412dd70986c0c987ba7344b9037387516d258e7885b51f8968b7f2601213bc4cb4c85f8ff0b84af6a988337cdfb81868f7e",
    "cf31dca6716d7ec2dd802c1672629e5c0052cb357dd29aafc43f615b3b1ff9d4e1ce08c71c73e1febb7dc56a33621329e9ed6c2302030100",
    "01a382024e3082024a300c0603551d13040530030101ff300e0603551d0f0101ff0404030201c6301d0603551d0e04160414fa550d8c3466",
    "51434cf7e7b3a76c95af7ae6a4973081ca0603551d230481c23081bf8014fa550d8c346651434cf7e7b3a76c95af7ae6a497a1819ba48198",
    "3081953111300f060355040a130846726565205453413110300e060355040b1307526f6f74204341311830160603550403130f7777772e66",
    "7265657473612e6f72673122302006092a864886f70d0109011613627573696c657a617340676d61696c2e636f6d31123010060355040713",
    "09577565727a62757267310f300d0603550408130642617965726e310b3009060355040613024445820900c1e986160da8e9803033060355",
    "1d1f042c302a3028a026a0248622687474703a2f2f7777772e667265657473612e6f72672f726f6f745f63612e63726c3081cf0603551d20",
    "0481c73081c43081c1060a2b0601040181f22401013081b2303306082b060105050702011627687474703a2f2f7777772e66726565747361",
    "2e6f72672f667265657473615f6370732e68746d6c303206082b060105050702011626687474703a2f2f7777772e667265657473612e6f72",
    "672f667265657473615f6370732e706466304706082b06010505070202303b1a394672656554534120747275737465642074696d65737461",
    "6d70696e6720536f6674776172652061732061205365727669636520285361615329303706082b06010505070101042b3029302706082b06",
    "010505073001861b687474703a2f2f7777772e667265657473612e6f72673a32353630300d06092a864886f70d01010d0500038202010068",
    "af7ebf938562ef4ceb3b580be2faf6cc35a26772962f3d95901fa5630c87d09198984ce8a06a33f8a9c282ed9f1cb11ac6c23e17108ee4ef",
    "ce6fb294de95c133262255725522ca61971d4a3b7f78250dfb8d4aeec0fb1959b164100520b9c10e64c62662e4ad4d0abae2298fc948fc4e",
    "99e8d9e6b8fdbe4404121ec7c1422eacb2c9d7328e07396e60b4f3bb803ad4a555c80fefb53f85e7764a0a9fb4afc399f4cd2f5fbf587105",
    "c6081cf3d05337b6bb7d1b010b749f4888c912f3696ba1b6902d77b7dfc046c04a0cc1ec4f8d185e2da55dfb7bc2a2036c6219246a4f99dd",
    "bb6f1f829398f3b803dc0ad90dcb59bef4c27c77404b99043b78271867991152c399f12cbfc4c625adc096355ae44e342100ec517a502e2f",
    "06f940b8d43599bbc1154f8ae761a0b0d555fb4a1391d4f3420af8dbf12f2d7ddb9d77dce1537804074af175e4f2d6d55b34b5d6f7dcbdd3",
    "1730af56480d4c0cff143f9e83bc151866d0ba0f0bbdc47fe27864176bbd6c1ab85df325edf777889bc4471bf3fa73e56cc591e8b160cda7",
    "b0786a1ec04ac3b24fa2e28d5d19e5e48004d5e166a83c82ec6fd54fb385ebaf7133a85b52de46db5244e1c34ae8d36e712f9fce0d493d7d",
    "3edd586c6198e3ec3e6e96346f417ac9f221e0aff33a8f6a0b1ef4c023630b76adaa8d91433825ecc41c49a5b98b181c7da30e997ab954c7",
    "3c2cd805afda993182038a308203860201013081a33081953111300f060355040a130846726565205453413110300e060355040b1307526f",
    "6f74204341311830160603550403130f7777772e667265657473612e6f72673122302006092a864886f70d0109011613627573696c657a61",
    "7340676d61696c2e636f6d3112301006035504071309577565727a62757267310f300d0603550408130642617965726e310b300906035504",
    "0613024445020900c1e986160da8e982300d06096086480165030402030500a081b8301a06092a864886f70d010903310d060b2a864886f7",
    "0d0109100104301c06092a864886f70d010905310f170d3235303832393037353330305a302b060b2a864886f70d010910020c311c301a30",
    "1830160414916da3d860ecca82e34bc59d1793e7e968875f14304f06092a864886f70d010904314204401d3b1f355cc995b2c7a38dfee19a",
    "0815ae93a9078cea6db540501eedf305e9f9f41349096a089bf5358380d6ed01eb508cbb551d120e9aca924429148ef1a229300d06092a86",
    "4886f70d0101010500048202004f22fe5e554c950f7f74462adde4f7c4c412d60479c6950c2509d1a5063e04c284eb42dda42e3591447b63",
    "fdc72c953ef04c81c1e59874c4d02cfb6b63de977d439998995e960a25755304a12ed23e7ccae97678a3dd94bc4025399806c9d00454a740",
    "800d3dc13016143af48b80c1d24033694f2bedb7c25d35c065e9c2fe71cee598ac2e8700bed5b755f001da3227f85fc178f27c56564ef5ff",
    "64b874916ab6fd2d966c542936a9940d0a5685463dc8e5b6ee82d639abb683433603541db3362ad77667e2ded4160c8f87e5c048d6bd05a7",
    "831871bb1052ddac132f35baadc2ceea41834efd276d4d2a8525879bd909b3d930d3cd4ef1d87d1a5f47bd9bef00956fee8e55d2d40b7447",
    "074a7295b204f07ee086775729d9cdb5940795612722388cb3af8a96fac65c79179c7e5292ce06e3f582e3f7d8fa6d7d41759bbd593b32a0",
    "fac8149a2b015e795fca2810133c2d768ef8d9da66ba192cbf142d2e4571e491ed7f7b0eb920f22c4492ba0260d30fef98a4d503693afe3d",
    "cc561b04bb3b32d8a49f27f988fefaa5f7b1af110bdad64a2825348a46651e1371e625c9792dfe9780528e5eb17f6078fcb418a420129e7a",
    "19bf8f27508b256e755753d8e6b436c384fa350c2e4e9018fd372cf54f303d462832675c8ac89f04c360a1d0d82f8d52ff7d815e74ad4aa1",
    "9a68a9acfd2450855dcb3b2a528063d426dc30268f",
);
const RFC9921_SIGNATURE_HEX: &str = "8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36";

fn fixture_key() -> CanonicalPublicCoseKey {
    CanonicalPublicCoseKey::ed25519(
        hex::decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap()
}

fn sign_core(
    signer: &CoseSigner,
    content_type: ContentType,
    certificate: CertificateHash,
    core: &[u8],
) -> Result<Vec<u8>, ea_crypto::CryptoError> {
    match content_type {
        ContentType::ChallengeResponseCbor => signer.sign_challenge_response(core),
        ContentType::ReaderAckCbor => signer.sign_reader_ack(core),
        ContentType::CheckpointCbor => signer.sign_checkpoint(certificate, core),
        ContentType::EvidenceRenewalCbor => signer.sign_evidence_renewal(certificate, core),
        ContentType::LocalAuditCbor => signer.sign_local_audit(core),
        _ => Err(ea_crypto::CryptoError::InvalidCose),
    }
}

fn cbor_bstr(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(bytes.len() + 3);
    match bytes.len() {
        length @ 0..=23 => encoded.push(0x40 | u8::try_from(length).unwrap()),
        length @ 24..=255 => encoded.extend_from_slice(&[0x58, u8::try_from(length).unwrap()]),
        length => encoded.extend_from_slice(&[
            0x59,
            u8::try_from(length >> 8).unwrap(),
            u8::try_from(length & 0xff).unwrap(),
        ]),
    }
    encoded.extend_from_slice(bytes);
    encoded
}

fn raw_cose_sign1(
    protected: &[u8],
    unprotected: &[u8],
    payload: Option<&[u8]>,
    signature: &[u8],
    tagged: bool,
) -> Vec<u8> {
    let mut encoded = Vec::new();
    if tagged {
        encoded.push(0xd2);
    }
    encoded.push(0x84);
    encoded.extend_from_slice(&cbor_bstr(protected));
    encoded.extend_from_slice(unprotected);
    if let Some(payload) = payload {
        encoded.extend_from_slice(&cbor_bstr(payload));
    } else {
        encoded.push(0xf6);
    }
    encoded.extend_from_slice(&cbor_bstr(signature));
    encoded
}

fn replace_once(bytes: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("negative fixture needle must occur");
    let mut output = Vec::with_capacity(bytes.len() - needle.len() + replacement.len());
    output.extend_from_slice(&bytes[..offset]);
    output.extend_from_slice(replacement);
    output.extend_from_slice(&bytes[offset + needle.len()..]);
    output
}

#[test]
fn three_protected_profiles_match_hard_coded_wire_answers() {
    let thumbprint = fixture_key().thumbprint();
    let certificate =
        CertificateHash::try_from(
            &hex::decode("d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef")
                .unwrap()[..],
        )
        .unwrap();
    assert_eq!(
        hex::encode(
            ProtectedHeader::normal(ContentType::RecordDigest, thumbprint, certificate)
                .to_deterministic_cbor()
        ),
        NORMAL_PROTECTED_HEX
    );
    assert_eq!(
        hex::encode(ProtectedHeader::initial_root(thumbprint).to_deterministic_cbor()),
        INITIAL_ROOT_PROTECTED_HEX
    );
    assert_eq!(
        hex::encode(ProtectedHeader::enrollment(thumbprint).to_deterministic_cbor()),
        ENROLLMENT_PROTECTED_HEX
    );
    assert_eq!(
        hex::encode(
            ProtectedHeader::normal(ContentType::RecordDigest, thumbprint, certificate)
                .sig_structure_bytes(&[0x40; 32])
        ),
        "846a5369676e617475726531589aa50132028303046f63657274696669636174654861736803782b6170706c69636174696f6e2f766e642e65696e7361747a6172636869762e7265636f72642d646967657374045820be5de2f4bcdc383add3fc9827d345f1a37c6a06026b38696fb3229c003b35f496f6365727469666963617465486173685820d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef4058204040404040404040404040404040404040404040404040404040404040404040"
    );
}

#[test]
fn tag_18_attached_cose_round_trips_exactly_and_mutations_fail() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let payload: [u8; 32] = std::array::from_fn(|index| 0x40 + index as u8);
    let encoded = signer.sign_initial_root(&payload).unwrap();
    let parsed = parse_cose_sign1(&encoded, &[]).unwrap();
    assert_eq!(parsed.exact_bytes(), encoded);
    assert_eq!(parsed.payload(), payload);
    assert!(parse_cose_sign1(&encoded, b"not empty").is_err());

    for index in 0..encoded.len() {
        let mut mutated = encoded.clone();
        mutated[index] ^= 1;
        if parse_cose_sign1(&mutated, &[]).is_ok() {
            assert!(fixture_key().verify_strict(&mutated).is_err());
        }
    }
}

#[test]
fn root_and_enrollment_profiles_have_separate_verifiers() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let payload = [0x55; 32];
    let root = signer.sign_initial_root(&payload).unwrap();
    assert!(verify_initial_root_pop(&root, &fixture_key(), &payload).is_ok());
    assert!(verify_enrollment_pop(&root, &fixture_key(), &payload).is_err());

    let unsigned_core = hex::decode("890150000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f005828a30101200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8f68101817545494e5341545a4152434849562d53554954452d3180").unwrap();
    let enrollment = signer.sign_enrollment(&unsigned_core).unwrap();
    assert!(verify_enrollment_pop(&enrollment, &fixture_key(), &unsigned_core).is_ok());
    assert!(verify_initial_root_pop(&enrollment, &fixture_key(), &unsigned_core).is_err());
}

#[test]
fn closed_content_type_registry_rejects_runtime_values() {
    let registry = [
        (
            ContentType::RecordDigest,
            "application/vnd.einsatzarchiv.record-digest",
        ),
        (
            ContentType::GrantDigest,
            "application/vnd.einsatzarchiv.grant-digest",
        ),
        (
            ContentType::ReceiptDigest,
            "application/vnd.einsatzarchiv.receipt-digest",
        ),
        (
            ContentType::TrustDigest,
            "application/vnd.einsatzarchiv.trust-digest",
        ),
        (
            ContentType::CheckpointCbor,
            "application/vnd.einsatzarchiv.checkpoint+cbor",
        ),
        (
            ContentType::EvidenceRenewalCbor,
            "application/vnd.einsatzarchiv.evidence-renewal+cbor",
        ),
        (
            ContentType::LocalAuditCbor,
            "application/vnd.einsatzarchiv.local-audit+cbor",
        ),
        (
            ContentType::ChallengeResponseCbor,
            "application/vnd.einsatzarchiv.challenge-response+cbor",
        ),
        (
            ContentType::DeviceRegistrationRequestCbor,
            "application/vnd.einsatzarchiv.device-registration-request+cbor",
        ),
        (
            ContentType::ReaderAckCbor,
            "application/vnd.einsatzarchiv.reader-ack+cbor",
        ),
        (
            ContentType::RecoveryTestDigest,
            "application/vnd.einsatzarchiv.recovery-test-digest",
        ),
    ];
    for (content_type, wire) in registry {
        assert_eq!(content_type.as_str(), wire);
        assert_eq!(ContentType::try_from(wire).unwrap(), content_type);
    }
    assert!(ContentType::try_from("application/vnd.einsatzarchiv.unknown").is_err());
}

#[test]
fn protocol_cores_and_signed_wrappers_match_normative_golden_bytes() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let certificate = CertificateHash::try_from(
        hex::decode("d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef")
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let cases = [
        (
            ContentType::ChallengeResponseCbor,
            CHALLENGE_CORE_HEX,
            CHALLENGE_COSE_HEX,
            CHALLENGE_WRAPPER_HEX,
            false,
        ),
        (
            ContentType::DeviceRegistrationRequestCbor,
            REGISTRATION_CORE_HEX,
            REGISTRATION_COSE_HEX,
            REGISTRATION_WRAPPER_HEX,
            true,
        ),
        (
            ContentType::ReaderAckCbor,
            READER_ACK_CORE_HEX,
            READER_ACK_COSE_HEX,
            READER_ACK_WRAPPER_HEX,
            false,
        ),
    ];

    for (content_type, core_hex, cose_hex, wrapper_hex, enrollment) in cases {
        let core = hex::decode(core_hex).unwrap();
        validate_unsigned_protocol_core(content_type, &core).unwrap();
        let cose = if enrollment {
            signer.sign_enrollment(&core).unwrap()
        } else {
            sign_core(&signer, content_type, certificate, &core).unwrap()
        };
        assert_eq!(hex::encode(&cose), cose_hex);

        let expected_wrapper = hex::decode(wrapper_hex).unwrap();
        let wrapper = encode_signed_protocol_wrapper(content_type, &core, &cose).unwrap();
        assert_eq!(wrapper, expected_wrapper);
        assert!(validate_unsigned_protocol_core(content_type, &wrapper).is_err());
        assert!(
            encode_signed_protocol_wrapper(content_type, &wrapper, &cose).is_err(),
            "a final wrapper must never be accepted as unsigned core"
        );

        let mut self_referential_core = core[..core.len() - 1].to_vec();
        self_referential_core.push(0x81);
        self_referential_core.extend_from_slice(&cose);
        assert!(
            validate_unsigned_protocol_core(content_type, &self_referential_core).is_err(),
            "the reserved empty array cannot contain its own signature"
        );
        if enrollment {
            assert!(signer.sign_enrollment(&wrapper).is_err());
        } else {
            assert!(sign_core(&signer, content_type, certificate, &wrapper).is_err());
        }
    }
}

#[test]
fn protocol_wrapper_rejects_signature_for_a_different_core_or_content_type() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let challenge = hex::decode(CHALLENGE_CORE_HEX).unwrap();
    let reader_ack = hex::decode(READER_ACK_CORE_HEX).unwrap();
    let challenge_signature = signer.sign_challenge_response(&challenge).unwrap();

    assert!(
        encode_signed_protocol_wrapper(
            ContentType::ReaderAckCbor,
            &reader_ack,
            &challenge_signature,
        )
        .is_err()
    );
    let mut changed_challenge = challenge;
    changed_challenge[20] ^= 1;
    assert!(
        encode_signed_protocol_wrapper(
            ContentType::ChallengeResponseCbor,
            &changed_challenge,
            &challenge_signature,
        )
        .is_err()
    );
}

#[test]
fn rfc9921_ctt_imprint_and_exact_token_header_match_published_bytes() {
    let signature: [u8; 64] = hex::decode(RFC9921_SIGNATURE_HEX)
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        hex::encode(cose_sign1_ctt_imprint(&signature).as_bytes()),
        "44c2419d131d53d55584b5dd33b788c24e551c6d44b1afc8b2b85e6954763b4e"
    );

    let token_der = hex::decode(RFC9921_TOKEN_HEX).unwrap();
    assert_eq!(token_der.len(), 0x154d);
    let token = UnverifiedRfc3161TimeStampToken::from_der(&token_der).unwrap();
    assert_eq!(token.as_der(), token_der);

    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let certificate = CertificateHash::try_from([0xd0; 32].as_slice()).unwrap();
    for (content_type, core_hex) in [
        (ContentType::CheckpointCbor, CHECKPOINT_CORE_HEX),
        (ContentType::EvidenceRenewalCbor, RENEWAL_CORE_HEX),
    ] {
        let core = hex::decode(core_hex).unwrap();
        let base = sign_core(&signer, content_type, certificate, &core).unwrap();
        let timestamped = attach_rfc3161_ctt(&base, &token).unwrap();
        let parsed = parse_cose_sign1(&timestamped, &[]).unwrap();
        assert_eq!(parsed.timestamp_token(), Some(token_der.as_slice()));

        let exact_unprotected = hex::decode(format!("a119010e59154d{RFC9921_TOKEN_HEX}")).unwrap();
        assert_eq!(
            timestamped
                .windows(exact_unprotected.len())
                .filter(|window| *window == exact_unprotected)
                .count(),
            1
        );
        assert!(attach_rfc3161_ctt(&timestamped, &token).is_err());
    }

    let record = signer.sign_initial_root(&[0x40; 32]).unwrap();
    assert!(attach_rfc3161_ctt(&record, &token).is_err());
}

#[test]
fn complete_timestamp_response_is_never_accepted_as_label_270_token() {
    let token_der = hex::decode(RFC9921_TOKEN_HEX).unwrap();
    let complete_response_der =
        hex::decode(format!("308215523003020100{RFC9921_TOKEN_HEX}")).unwrap();
    assert_eq!(complete_response_der.len(), 0x1556);
    assert_ne!(complete_response_der, token_der);
    assert!(UnverifiedRfc3161TimeStampToken::from_der(&complete_response_der).is_err());

    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let certificate = CertificateHash::try_from([0xd0; 32].as_slice()).unwrap();
    let checkpoint = hex::decode(CHECKPOINT_CORE_HEX).unwrap();
    let base = signer.sign_checkpoint(certificate, &checkpoint).unwrap();
    let mut decoder = minicbor::Decoder::new(&base);
    decoder.tag().unwrap();
    decoder.array().unwrap();
    decoder.bytes().unwrap();
    let unprotected_offset = decoder.position();
    assert_eq!(base[unprotected_offset], 0xa0);

    let response_header = hex::decode("a119010e591556").unwrap();
    let invalid = [
        &base[..unprotected_offset],
        response_header.as_slice(),
        complete_response_der.as_slice(),
        &base[unprotected_offset + 1..],
    ]
    .concat();
    assert!(
        parse_cose_sign1(&invalid, &[]).is_err(),
        "a complete TimeStampResp must not be confused with its embedded ContentInfo"
    );
}

#[test]
fn empty_cms_signed_data_shell_is_not_a_timestamp_token() {
    let empty_signed_data_shell = hex::decode("300f06092a864886f70d010702a0023000").unwrap();

    let error = match UnverifiedRfc3161TimeStampToken::from_der(&empty_signed_data_shell) {
        Ok(_) => panic!("an empty SignedData shell is not a timestamp token"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "EA-CRYPTO-INVALID-COSE");
}

#[test]
fn archive_evidence_and_local_audit_payloads_are_closed_cddl_shapes() {
    let cases = [
        (ContentType::CheckpointCbor, CHECKPOINT_CORE_HEX),
        (ContentType::EvidenceRenewalCbor, RENEWAL_CORE_HEX),
        (ContentType::LocalAuditCbor, LOCAL_AUDIT_CORE_HEX),
    ];

    for (content_type, golden) in cases {
        let core = hex::decode(golden).unwrap();
        validate_unsigned_protocol_core(content_type, &core).unwrap();

        let mut wrong_version = core.clone();
        wrong_version[1] = 2;
        assert!(validate_unsigned_protocol_core(content_type, &wrong_version).is_err());

        let mut nonempty_reserved = core[..core.len() - 1].to_vec();
        nonempty_reserved.extend_from_slice(&[0x81, 0x00]);
        assert!(validate_unsigned_protocol_core(content_type, &nonempty_reserved).is_err());
    }

    let mut wrong_checkpoint_domain = hex::decode(CHECKPOINT_CORE_HEX).unwrap();
    wrong_checkpoint_domain[7] ^= 1;
    assert!(
        validate_unsigned_protocol_core(ContentType::CheckpointCbor, &wrong_checkpoint_domain)
            .is_err()
    );

    let mut unsorted_renewal = hex::decode(RENEWAL_CORE_HEX).unwrap();
    let first = unsorted_renewal
        .iter()
        .position(|byte| *byte == 0x40)
        .unwrap();
    unsorted_renewal[first] = 0x70;
    assert!(
        validate_unsigned_protocol_core(ContentType::EvidenceRenewalCbor, &unsorted_renewal)
            .is_err()
    );

    let mut mismatched_audit_context = hex::decode(LOCAL_AUDIT_CORE_HEX).unwrap();
    let context_tag = mismatched_audit_context
        .windows(3)
        .position(|window| window == [0x82, 0x00, 0xf6])
        .unwrap()
        + 1;
    mismatched_audit_context[context_tag] = 1;
    assert!(
        validate_unsigned_protocol_core(ContentType::LocalAuditCbor, &mismatched_audit_context)
            .is_err()
    );
}

#[test]
fn enrollment_pop_is_bound_only_to_its_embedded_ed25519_signing_key() {
    let signer =
        CoseSigner::from_secret(SecretBytes::new(std::array::from_fn(|index| index as u8)));
    let certificate = CertificateHash::try_from([0xd0; 32].as_slice()).unwrap();
    let core = hex::decode(REGISTRATION_CORE_HEX).unwrap();

    assert!(
        sign_core(
            &signer,
            ContentType::DeviceRegistrationRequestCbor,
            certificate,
            &core
        )
        .is_err()
    );

    let mut mismatched_core = core.clone();
    let old_key =
        hex::decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8").unwrap();
    let offset = mismatched_core
        .windows(32)
        .position(|window| window == old_key)
        .unwrap();
    mismatched_core[offset..offset + 32].copy_from_slice(
        &hex::decode("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12").unwrap(),
    );
    validate_unsigned_protocol_core(ContentType::DeviceRegistrationRequestCbor, &mismatched_core)
        .unwrap();
    assert!(signer.sign_enrollment(&mismatched_core).is_err());

    let pop = signer.sign_enrollment(&core).unwrap();
    let wrong_key = CanonicalPublicCoseKey::ed25519(
        hex::decode("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    assert!(verify_enrollment_pop(&pop, &wrong_key, &core).is_err());
}

#[test]
fn named_cose_profile_negatives_all_fail_closed() {
    let thumbprint = fixture_key().thumbprint();
    let certificate = CertificateHash::try_from([0xd0; 32].as_slice()).unwrap();
    let normal = ProtectedHeader::normal(ContentType::RecordDigest, thumbprint, certificate)
        .to_deterministic_cbor();
    let payload = [0x40; 32];
    let signature = [0_u8; 64];
    let valid_wire = raw_cose_sign1(&normal, &[0xa0], Some(&payload), &signature, true);
    parse_cose_sign1(&valid_wire, &[]).unwrap();

    let mut deprecated_algorithm = normal.clone();
    deprecated_algorithm[2] = 0x27;
    let unknown_content_type = replace_once(&normal, b"record-digest", b"xecord-digest");
    let missing_crit_entry = replace_once(&normal, &[0x83, 0x03, 0x04], &[0x82, 0x03, 0x04]);
    let duplicate_crit_entry = replace_once(&normal, &[0x83, 0x03, 0x04], &[0x83, 0x03, 0x03]);
    let reordered_crit_entries = replace_once(&normal, &[0x83, 0x03, 0x04], &[0x83, 0x04, 0x03]);
    let wrongly_typed_crit_entry = replace_once(
        &normal,
        &[0x83, 0x03, 0x04, 0x6f],
        &[0x83, 0x03, 0x61, b'4', 0x6f],
    );
    let unknown_crit_entry = replace_once(&normal, &[0x83, 0x03, 0x04], &[0x83, 0x03, 0x05]);

    let checkpoint = hex::decode(CHECKPOINT_CORE_HEX).unwrap();
    let checkpoint_protected =
        ProtectedHeader::normal(ContentType::CheckpointCbor, thumbprint, certificate)
            .to_deterministic_cbor();
    let registration = hex::decode(REGISTRATION_CORE_HEX).unwrap();
    let normal_registration = ProtectedHeader::normal(
        ContentType::DeviceRegistrationRequestCbor,
        thumbprint,
        certificate,
    )
    .to_deterministic_cbor();
    let reader_ack_protected =
        ProtectedHeader::normal(ContentType::ReaderAckCbor, thumbprint, certificate)
            .to_deterministic_cbor();
    let challenge = hex::decode(CHALLENGE_CORE_HEX).unwrap();

    let fixtures = [
        (
            "deprecated alg -8",
            raw_cose_sign1(
                &deprecated_algorithm,
                &[0xa0],
                Some(&payload),
                &signature,
                true,
            ),
        ),
        (
            "unknown content type",
            raw_cose_sign1(
                &unknown_content_type,
                &[0xa0],
                Some(&payload),
                &signature,
                true,
            ),
        ),
        (
            "missing crit entry",
            raw_cose_sign1(
                &missing_crit_entry,
                &[0xa0],
                Some(&payload),
                &signature,
                true,
            ),
        ),
        (
            "duplicate crit entry",
            raw_cose_sign1(
                &duplicate_crit_entry,
                &[0xa0],
                Some(&payload),
                &signature,
                true,
            ),
        ),
        (
            "reordered crit entries",
            raw_cose_sign1(
                &reordered_crit_entries,
                &[0xa0],
                Some(&payload),
                &signature,
                true,
            ),
        ),
        (
            "wrongly typed crit entry",
            raw_cose_sign1(
                &wrongly_typed_crit_entry,
                &[0xa0],
                Some(&payload),
                &signature,
                true,
            ),
        ),
        (
            "unknown crit entry",
            raw_cose_sign1(
                &unknown_crit_entry,
                &[0xa0],
                Some(&payload),
                &signature,
                true,
            ),
        ),
        (
            "non-empty unprotected header",
            raw_cose_sign1(
                &normal,
                &[0xa1, 0x01, 0x00],
                Some(&payload),
                &signature,
                true,
            ),
        ),
        (
            "unknown CTT unprotected label",
            raw_cose_sign1(
                &checkpoint_protected,
                &[0xa1, 0x19, 0x01, 0x0f, 0x41, 0x00],
                Some(&checkpoint),
                &signature,
                true,
            ),
        ),
        (
            "detached payload",
            raw_cose_sign1(&normal, &[0xa0], None, &signature, true),
        ),
        (
            "missing Tag 18",
            raw_cose_sign1(&normal, &[0xa0], Some(&payload), &signature, false),
        ),
        (
            "wrong signature length",
            raw_cose_sign1(&normal, &[0xa0], Some(&payload), &signature[..63], true),
        ),
        (
            "mismatched payload and content type",
            raw_cose_sign1(
                &reader_ack_protected,
                &[0xa0],
                Some(&challenge),
                &signature,
                true,
            ),
        ),
        (
            "ordinary normal enrollment profile",
            raw_cose_sign1(
                &normal_registration,
                &[0xa0],
                Some(&registration),
                &signature,
                true,
            ),
        ),
    ];

    for (name, fixture) in fixtures {
        assert!(
            parse_cose_sign1(&fixture, &[]).is_err(),
            "negative COSE fixture unexpectedly parsed: {name}"
        );
    }
    assert!(parse_cose_sign1(&valid_wire, b"non-empty external aad").is_err());
}
