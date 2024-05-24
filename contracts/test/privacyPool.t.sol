pragma solidity ^0.8.4;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/Create2.sol";
import "../src/PrivacyPool.sol";
import "../src/Groth16Verifier.sol";
import "../src/TreeHasher.sol";
import "../src/interfaces/IPrivacyPool.sol";

contract TestPrivacyPool is Test {
    IPrivacyPool internal pool;
    Groth16Verifier internal verifier;
    TreeHasher internal hasher;
    Create2 internal create2;

    function setUp() public {
        verifier = new Groth16Verifier();
        hasher = new TreeHasher();
        create2 = new Create2();

        vm.deal(address(0x1), 100 ether);
        vm.startPrank(address(0x1));
        bytes32 salt = "12345";
        bytes memory creationCode = abi.encodePacked(
            type(PrivacyPool).creationCode,
            abi.encode(
                address(verifier), address(hasher), uint256(2 ** 248), 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE
            )
        );

        address computedAddress = create2.computeAddress(salt, keccak256(creationCode));
        address deployedAddress = create2.deploy(salt, creationCode);
        vm.stopPrank();

        assertEq(computedAddress, deployedAddress);

        pool = IPrivacyPool(deployedAddress);
        console.log("deployedAddress: ", deployedAddress);
        console.log("valueUnitRepresentative: ", pool.valueUnitRepresentative());
        console.log("currentDepth: ", pool.currentDepth());
        console.log("latestRoot: ", pool.latestRoot());
        console.log("size: ", pool.size());
    }

    function testCalcSignalHash() public {
        uint256 hash = pool.calcSignalHash(
            100, 0, 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE, 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE
        );
        assertEq(hash, 18937175923520281763335632801636284365647507147689795808174989680533635809126);
    }

    function testCalcPublicVal() public {
        uint256 publicVal = pool.calcPublicVal(-250, 50);
        assertEq(publicVal, 21888242871839275222246405745257275088548364400416034343698204186575808495317);
    }

    function testProcess() public {
        vm.deal(address(0x1), 1000000 ether);
        vm.startPrank(address(0x1));

        // Fresh Tree, 2 zero Input, 1 zero Output, 1 non-zero Output
        pool.process{value: 100}(
            IPrivacyPool.signal({
                units: 100,
                fee: 0,
                account: 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE,
                feeCollector: 0xA9959D135F54F91b2f889be628E038cbc014Ec62
            }),
            IPrivacyPool.supplement({
                ciphertexts:  [
                    [ 17588862741843131082337577935358552371170778516033212183365614551518659773346,
                        4125601494320332492076953011842000903576601516917908821085402444016305661350,
                        13342677508392806767808539556594287698128087331704768524131881015569729555929,
                        163697314622228675136829286761239272268836883361137323743371874367986844187
                    ], [ 17588862741843131082337577935358552371170778516033212183365614551518659773246,
                        4125601494320332492076953011842000903576601516917908821085402444016305661333,
                        13342677508392806767808539556594287698128087331704768524131881015569729555929,
                        8267046481794314775832600901667384382294486624816811174417461243939837809584
                    ]
                ],
                associationProofURI: "ipfs://"
            }),
            [0x24fa117931ab6db6d40d7806a86e8bb44a45dcb30f971b1f46c7efffac729fb9, 0x0e28eab571ae5006f7168a7e9fc5a0da7aff717c47166622360f8f8165a01431],[[0x064c9db6a87eeb2083e2a51b09691b653bc51c1cf92c6a8bd7276e495327c649, 0x0fd88672772bc3d47027dfc243bdcbd0af7b7a707eee29085de09527727d56cf],[0x2d013ff18e7608669bccbb08c9ffa94fd2ed4fad71adfdc2f457c8b79bf9f5a1, 0x299a381107435236eb93d30cec367a5cbf70a86601f590e66fd9d11aabb7cab2]],[0x06f02caa4b539891339255d92ae4d297c0b12e1290c373fef3f2513025223cda, 0x06e50f4649491735474d6ce6cf5306b350ada70dda18a3c1aa37297d70a7f164],[0x0000000000000000000000000000000000000000000000000000000000000000,0x0000000000000000000000000000000000000000000000000000000000000064,0x0c138d79d2a0c9f1eb742d55eae4a3351dcae0a65eccbf3748c73ad56de9ab93,0x0000000000000000000000000000000000000000000000000000000000000000,0x1453ea5b975aa0fb1fd7c3bb8fba0fbfd2b618ff082ac831154f50b70ae62fbf,0x2677db95f3e68fc4f7e5b6029aeda09825a43536de1f9f9167fe92b8d3a80813,0x08ab66ff4b5457e3cf0856539bd5a400ccb87d40d7c4c3ba16965f962d0fd044,0x26eeb8ab25513e324528200c90f9a413e4ebfbd31a8047601464c4e4721756c6]
        );

        console.log("latestRoot: ", pool.latestRoot());

        pool.process{value: 200}(
            IPrivacyPool.signal({
                units: 200,
                fee: 0,
                account: 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE,
                feeCollector: 0xA9959D135F54F91b2f889be628E038cbc014Ec62
            }),
            IPrivacyPool.supplement({
                ciphertexts:  [
                [ 3273021390891633812810828464935003741245853985210934569521564743729930825071,
                    16815839399694819246934879233229362826788764227866412305199469645115186961697,
                    7860771625442621689151057388170157150256599955557218603418608316462009975817,
                    6946575645045455229738366258612051806347611772525401808405017546678535912601
                ], [ 17588862741843131082337577935358552371170778516033212183365614551518659773246,
                    4125601494320332492076953011842000903576601516917908821085402444016305661386,
                    13342677508392806767808539556594287698128087331704768524131881015569729555929,
                    15012799090476148329087151639092145073495730851861930784652331011666922369789
                ]
                ],
                associationProofURI: "ipfs://"
            }),
            [0x27425ea4a7a823085ab86f07045600395b13e446922935f7c96a1076f4e00d6c, 0x15762396ff66a6fdb3aae5a7d583637eaa22153d9d17f05bc5fad3c92c9a8389],[[0x13e83abf4a42beed082933ad0fae56822a25fbf5d53f03afaec3ac4f83270d3d, 0x074d66f82ae525d36bb819269169257233ee0de8323d0af6d8358d82c9b5d954],[0x0615f4800ce6594b9d84cac6b3462f1ea09988a4cd1b523824a29a97eaeeb15a, 0x2ccb28b4f4583f503d3cc3a698cb93ef9963d4fd32efb1e053af693c0dd7720a]],[0x182078bde2dd16ccf677ee7bef79ca40948a29770221dfecb9155c2d3b59fe43, 0x21f496932eda1f523dc5571156867334b2200884e26c8c59323d6a72ab384b3a],[0x0d441a8738b8a522b72fdb6a2b6e9fdc4a29176e4befdbadcfc71e7c3acc9ad6,0x00000000000000000000000000000000000000000000000000000000000000c8,0x2a1fa261994753876355df8a85147bb56a148ba300462add27079fa63ae7bd2b,0x0000000000000000000000000000000000000000000000000000000000000001,0x093954e7999b11f5b784edeb4dda815f3b9aa9523179e760edf245127c224440,0x2f9d15bf6647a7d5c434525304ef1eeb564e5f95b7ff7859e7c739fd308613d3,0x0294f55cf6a8a62cd49d27a622e0bfc2732a41a781ab9acd65239ce1f6d39641,0x16a5b92fad2524ebe7faf768c6c9c23b7e9ca4467f7106d075800e4badfb32a4]
        );

        console.log("latestRoot: ", pool.latestRoot());

        pool.process(
            IPrivacyPool.signal({
                units: -250,
                fee: 50,
                account: 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE,
                feeCollector: 0xA9959D135F54F91b2f889be628E038cbc014Ec62
            }),
            IPrivacyPool.supplement({
                ciphertexts:  [
                [ 11814057539558329289247122853292353785675358043946561064779492861600855915725,
                    15354564672105173661636763174994812719396313706498890530994121505255968468040,
                    16044103204170799635423229381553994721555492541268308411320603072313006410067,
                    14559036612566924692620967854946789032842850159586582514024557006292111270807
                ], [ 17588862741843131082337577935358552371170778516033212183365614551518659773246,
                    4125601494320332492076953011842000903576601516917908821085402444016305661406,
                    13342677508392806767808539556594287698128087331704768524131881015569729555929,
                    1878545339145121440190417572122949788751110043496355788008963304807788242599
                ]
                ],
                associationProofURI: "ipfs://"
            }),
            [0x2f95994f90ddd9a68690abf944f29ade2dd196f2ac4e1df60be5017cf1ef506a, 0x1e1de80125ecefcd60576a3bffc4dc3212ab2bd5ea4ba04cdb0ddfd54e404bad],[[0x24a91e1a62d662ff356c4865f2cb6fa734b130e0e9cfc7fa2d5088e11fdbd077, 0x08d5bec29842e9cb69ebd998cd1f982e7e43b0f577696ea202a66043cdf503c9],[0x27fc4bc7a11f51e52be91d81db3672858a68946b85c178cbd2f4feb7e6262596, 0x1a6d3710811c474aaed714bfb276b6330f370ece5cb4028b583b8e440abf4533]],[0x183e13606a8abfc204845057fad8f020a0ac51e7e0b572ea11b07bdc64c19f5b, 0x0137174a305c8ea5d7a678b3fa01cfc24a7fc607913fd27f553ad2604c7d4457],[0x10b6ff28a1a15a62f1a7b6205507fe06e156b1c61291dc28b15b8a6bd75ead24,0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffed5,0x252cca98d44669f2fa40a57ed1b60a324ae274b246244bdd77d0f2b1bd657941,0x0000000000000000000000000000000000000000000000000000000000000002,0x0df6a0d4a9ce6b303ddc36549d7d92b078e146bb9e4158ad31dea8227f94a6c7,0x222aaf713e0ced59f58838702f3e1489f82e31bc107e7ddcda00650f7ea26873,0x036991e4d1ccc71145bf754096541ff2a44c0fa4532de39dde420b1cea99eda5,0x1a29cfc41561a322b7f64ce8ae4488c305e6bbac30071e62c4bc3d9326363bfe]
        );

        console.log("latestRoot: ", pool.latestRoot());

        uint256 AccBalance = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE).balance;
        console.log("AccBalance: ", AccBalance);

        assert(AccBalance == 250);

        uint256 feeCollector = address(0xA9959D135F54F91b2f889be628E038cbc014Ec62).balance;
        console.log("feeCollector: ", feeCollector);

        assert(feeCollector == 50);

        uint256 ContractBalance = address(pool).balance;
        console.log("ContractBalance: ", ContractBalance);

        assert(ContractBalance == 0);

        // PARTIAL RELEASE OF FUNDS

        pool.process{value: 99}(
            IPrivacyPool.signal({
                units: 99,
                fee: 0,
                account: 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE,
                feeCollector: 0xA9959D135F54F91b2f889be628E038cbc014Ec62
            }),
            IPrivacyPool.supplement({
                ciphertexts:  [
                [ 7054462040458467310734002774594840141536191411040388113690862933350371453362,
                    2560645406546409247582313779165996031425333430665960485164413625538515459232,
                    3927607733682043106196338802687002400706399479731776336058642956423048964989,
                    18593578739497005696549259156448343702097659472046967439103296089454396078734
                ], [ 17588862741843131082337577935358552371170778516033212183365614551518659773246,
                    4125601494320332492076953011842000903576601516917908821085402444016305661404,
                    13342677508392806767808539556594287698128087331704768524131881015569729555929,
                    69163421468781384189554513578853514708845343019831224870222899825199052723
                ]
                ],
                associationProofURI: "ipfs://"
            }),
            [0x04105fefa8ad90af95f5172fcb1ac17ec37c850a60a5c480d4948fd8d962cc51, 0x196ad9e6a5315614d1087950763435d480e755105fcbff4de770d3526458eb42],[[0x203416b3149616ae3831c44d524f3d0f03e3cfc4d2a630f7c1b9753b9f57ea95, 0x1138068a28f502429a78f82363a14d112fd7d7f68af0b4bc37e2d80979ea39bb],[0x031d1b70a3005ffbd5a6647a06a96037fca10ab27d65b4f977090d0c5ef4a51b, 0x1bca0f499141e4c8f34ccd51e7287d225f4fbd05fe6a077be246c5dcbf1c0970]],[0x27adbbec08a0147636fe1abdb3bf388e3808ce497be522f3eb86e9895fbb21eb, 0x2b7c709e56d60eb386203b93bd511151ec4eea1f5265f964512aab03c8c1dfcf],[0x0000000000000000000000000000000000000000000000000000000000000000,0x0000000000000000000000000000000000000000000000000000000000000063,0x13d94ef7dae2d14569918a00e8f792237c964b8220e05a51702dbc4957da1e71,0x0000000000000000000000000000000000000000000000000000000000000000,0x1c5c71284b7395c1966e27a8397a435a5f2a26e82162a7568c57693165fb491d,0x0b16960855f058e4525919a5b7decca642c72fc6ca80fa76fd28da4863c6d665,0x07e099e9cc54701eea3c5af758fed26596379c1abcd726ef6c8e9c0efdc71915,0x2389d0b9ff7af30bb4bfc88a8204971e1821fe17e2af66b541195af71d56b454]
        );

        console.log("latestRoot: ", pool.latestRoot());

        uint256 AccBalance2 = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE).balance;
        console.log("AccBalance: ", AccBalance2);

        assert(AccBalance2 == 250);

        uint256 feeCollector2 = address(0xA9959D135F54F91b2f889be628E038cbc014Ec62).balance;
        console.log("feeCollector: ", feeCollector2);

        assert(feeCollector2 == 50);

        uint256 ContractBalance2 = address(pool).balance;
        console.log("ContractBalance: ", ContractBalance2);

        assert(ContractBalance2 == 99);

        pool.process(
            IPrivacyPool.signal({
                units: -47,
                fee: 0,
                account: 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE,
                feeCollector: 0xA9959D135F54F91b2f889be628E038cbc014Ec62
            }),
            IPrivacyPool.supplement({
                ciphertexts:  [
                [ 1567417070148503670412576748973189497743330655692377693920779510853209823454,
                    810217875386723639263840921826910824322732481986902734225664200925175466146, 17795073905456084686438755921676514009004058878618164324090221266929139332599,
                    4710054776038011209224590516270600266425170912787899247339478719203229857564
                ], [ 17588862741843131082337577935358552371170778516033212183365614551518659773246,
                    4125601494320332492076953011842000903576601516917908821085402444016305661412,
                    13342677508392806767808539556594287698128087331704768524131881015569729555929,
                    20327548974115012102330827265531990445933844873483421858305939510503651277246
                ]
                ],
                associationProofURI: "ipfs://"
            }),
            [0x0237cc693d7c26a316d88119736f68c0053219e190a134f613a3acf368f967e8, 0x1b71d9db51a2f064735e874ed8457da2cda6c5da73c183ff74e0d2e6a4688c37],[[0x2384670604f15b1aadf48d56ccaf5332387b9a90e64fd766a79659b927d20d5b, 0x1fb498623e91fa88260c9deaf59934f1005ed83121f817f7f184a33da19a5444],[0x0a1bf3df8b6e6bff17a0f6eced0ff42bcc06d8dbcc1b92c3138037f11c41849a, 0x0d55156e45fba934ec7f3c70042945ba59dfdbc433bf1c7240ed92a5b3dbe74e]],[0x2959a0cde9bf1386aa2a0ee089bf8d9457d97d2d0cbb600021dc7d07214bba4e, 0x2c856a69039c05824bf92009e80c3d7bd2a2fa8013dbf24ac3ed0adbb3bda047],[0x0b18fab62fdf1eea12acc9279c1c0d0b17b1dd2ccde4e60c34af293bc82baa23,0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffd2,0x205467a515c8ef071d2d4a4e217e674bd2e2aa69ae2039028c0c8cad24c68fd5,0x0000000000000000000000000000000000000000000000000000000000000003,0x1babe638eafc12b6cb40e4c4310666699652fe4592f1a0c359eebdfe93b39061,0x044cdf5e83abdce10579bcd30d592ad61634391cf6d7bd11c856eeaf825ca3ef,0x2593a0a48330d8d88c2a89a04b0c569a6f9fd3e43d96ee8a68df2cd04fea6405,0x0ad089db588d28de605a27ba5831b3631751d5c4335b5bbf8b236f3614213a95]
        );

        console.log("latestRoot: ", pool.latestRoot());

        uint256 AccBalance3 = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE).balance;
        console.log("AccBalance: ", AccBalance3);

        assert(AccBalance3 == 297);

        
        uint256 feeCollector3 = address(0xA9959D135F54F91b2f889be628E038cbc014Ec62).balance;
        console.log("feeCollector: ", feeCollector3);

        assert(feeCollector3 == 50);

        uint256 ContractBalance3 = address(pool).balance;
        console.log("ContractBalance: ", ContractBalance3);

        assert(ContractBalance3 == 52);

        /* TODO
         - partial release + verify proof of innocence on 2nd release
         - release from commits from 2 different addresses
         - relayer can change fee value -> make sure they cant
        */

        vm.stopPrank();
    }
}
