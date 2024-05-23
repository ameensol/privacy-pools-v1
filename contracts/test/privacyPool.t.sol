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
                ciphertexts: [
                    [
                        11549330060325127860021207148469549495284128169849350740792214974175008723205,
                        16292388193260826995535660789093300345792985696734514982968656588422341755993,
                        15123695301333838834204737045590643350364109456840854030276580336696453767056,
                        7622618831135432345142082606951050052804739120504432540269219927854618709190
                    ],
                    [
                        11549330060325127860021207148469549495284128169849350740792214974175008723105,
                        16292388193260826995535660789093300345792985696734514982968656588422341756023,
                        15123695301333838834204737045590643350364109456840854030276580336696453767056,
                        4027335091046436867786961550789830172715739758512379857487580280084713712883
                    ]
                ],
                associationProofURI: "ipfs://"
            }),
            [0x01be3adf3655be1226cf82445b8b6dfe02d94e9cd1c6b4b33bcd79b11794b1f4, 0x103b9a45fee5e4bd53a04ef4d84ab399d3a50208abc02829136b63c24bec598f],[[0x10c97c6c3aad9817ee215533544149818ba3b6d12300ab4f044e31b2772d8f11, 0x1b45f281be675fbb3eb0e2d52ece13b73de7fb0c9aa81ed419b4b6ce9d11b6b2],[0x0133ce4a70b3ff4c9e7d978653d627f749b553bd5b29f4a4d02cdf23ce1fbf21, 0x20c9701e5cbe30571d870168d97dad146d8cd7a5beff980e4e07cc01ec047a4d]],[0x2e7cb633de0dbcfb9046ddfdfd2411ce605696381a97aab528fc67f571b2ff22, 0x0a2791b3fe664a172904bec347abe01dfb30ff0813c0ef059e398d225fac4938],[0x0000000000000000000000000000000000000000000000000000000000000000,0x0000000000000000000000000000000000000000000000000000000000000064,0x0c138d79d2a0c9f1eb742d55eae4a3351dcae0a65eccbf3748c73ad56de9ab93,0x0000000000000000000000000000000000000000000000000000000000000000,0x0043926dd31440f687e7c5bb8c0040e86bc2523cae06ceb59378d65bd8259182,0x0a24284c3898338b3e2f4e61da77fcc225d475a095982ae864689fd0606b8a57,0x251b69048f04e88ad590aef7393ffaf900156a58e05ce3351f0b8e6a172b26e1,0x1cc4cea55462fe4a70915cd7b61700407427899105d455f0fe41503a7fdbcb0c]
        );

        console.log("latestRoot: ", pool.latestRoot());

        /*

        pool.process{value: 200}(
            IPrivacyPool.signal({
                units: 200,
                fee: 0,
                account: 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE,
                feeCollector: 0xA9959D135F54F91b2f889be628E038cbc014Ec62
            }),
            IPrivacyPool.supplement({
                ciphertexts: [
                    [
                        9228064930188822699964540424001984067607556540390209272840245694915806878756,
                        6890129479135902374838110776107411674516471835923215973192869526242869775686,
                        3462718207616180355246120130527744094367885615321131034087649048382502301340,
                        13131650030008218146544827300043684013615967844740940294097965868461231911637
                    ],
                    [
                        11549330060325127860021207148469549495284128169849350740792214974175008723105,
                        16292388193260826995535660789093300345792985696734514982968656588422341755974,
                        15123695301333838834204737045590643350364109456840854030276580336696453767056,
                        10448475564968726195394786309252981777325818534705143147544876563855192367409
                    ]
                ],
                associationProofURI: "ipfs://"
            }),
            [0x0b7fc062b91d310bef024758f9c24a75bbfe4d3737e099bea95c65e3c8e886c5, 0x0a4848060c89d3be19cf90999bcb5e9b21d4a3851b029fce93865374c08de473],[[0x0205c27374d344e0a34d7a94e749d4a9d76971cdd934303fe0a153ee52a7a096, 0x2562df8e9f663930c03b77bafedd0b113743ba8d6fa1e7ee3be4cb04c68584fe],[0x1a37e66b687889906fed6ca54c7208ad50f736ff943e5c020d213e45504d4be6, 0x15c63b6feca4fd190c8fef79966701f360a12bbfe0ab74761e859ed0b18553c8]],[0x08239c162ac4bc9d983ce38127a2a727589985383be196ea15765401ef70598a, 0x06b848f61e13a2d8f697f304ace2997cddd4338b01f81143faff7e00b29f7eb9],[0x2fa7939be6f5611f81dd63c1a8a0ae85726805748e7abe30588afd934cb3ee51,0x00000000000000000000000000000000000000000000000000000000000000c8,0x2a1fa261994753876355df8a85147bb56a148ba300462add27079fa63ae7bd2b,0x0000000000000000000000000000000000000000000000000000000000000001,0x1b6654e21fc728280d3dab9367fe70435cb17829c85f6974ba82a14be8d2c761,0x0ee7754465a0cdba1867d1a8a92ef4c27c3ccf4feac74565d34a6ac5ac6c68c4,0x2a7a7f05f2db857439af17ef037730ec9f8410b6c4a66bba2ef4227315b7302c,0x27676b44529712275d983c2667d716c3f3cfde6b036d7836b9862189d01164d5]
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
                ciphertexts: [
                    [
                        4948253572082958349945287122336803355125230125652040150002380093966242282468,
                        4080804497337809083723856216771324275364056241979525998212376427238726785772,
                        15228619776601744614382028978950577645606538022742336779825399318319486388933,
                        17632846203487115857202326722569413163731087078376345707947863950467653928615
                    ],
                    [
                        11549330060325127860021207148469549495284128169849350740792214974175008723105,
                        16292388193260826995535660789093300345792985696734514982968656588422341756050,
                        15123695301333838834204737045590643350364109456840854030276580336696453767056,
                        21886674422972653358240045269728118599403096700381025834898077615188694671670
                    ]
                ],
                associationProofURI: "ipfs://"
            }),
            [0x14273045c2c97fbf2b408fb4fcf9bb46f37039b67e167433bbd117303637248c, 0x27c4726ac88f363598b74345936856ade2b3b1c0392f89cda0304e18c5cce2ec],[[0x1a6360b44b22e444d5934c448307c972ccd1ef5dd38cf4d3687de71f5af3a5a2, 0x002a0f4e5212d471127260c945cd3a6e619e088bb2b3fa6854ba8d06a4531cc0],[0x0310ffa2cb28050169d08c3b94cf49779df2e04a740a939ad22e2a98fcd2e1db, 0x09857681001e909adc28db07f5c1b9235276caf02b27d553506a2438b2be4faa]],[0x13de647fc4ff92dc6c4879d7622d4e1b5810f2e22e455f4ea463d3aa40494950, 0x062442d850c4fb5b4774b42fc26d351a353a707726188a8cafb699854286be8a],[0x1f7b45d4771ec3a6409d22dbb1ebebb46e8b8d23bec35a1600e51cf25246473d,0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffed5,0x252cca98d44669f2fa40a57ed1b60a324ae274b246244bdd77d0f2b1bd657941,0x0000000000000000000000000000000000000000000000000000000000000002,0x1469a490b5c93ba38b0f90eeccef50051197fbcf2a47387a7af7e7c923304314,0x24e259738106b0db50c6804bd3bcf4dae18b6eb7563c71d05a9de7525434107d,0x10b22259634f9742520f587df23571e346cb34c8d5320759012aa7d3a1289c95,0x1763707e98fb39a22953667802393fbd8a6ff8248b16bcfdab93df4717c58d7a]
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
        */

        vm.stopPrank();
    }
}
