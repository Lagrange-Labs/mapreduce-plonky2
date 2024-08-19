use alloy::rpc::types::EIP1186AccountProofResponse;
use eth_trie::Nibbles;
use mp2_common::{
    eth::{left_pad, ProofQuery},
    mpt_sequential::utils::visit_proof,
    rlp::MAX_KEY_NIBBLE_LEN,
    types::GFp,
    utils::{keccak256, Endianness, Packer, ToFields},
    C, D,
};
use mp2_test::circuit::{prove_circuit, setup_circuit};
use plonky2::field::types::Field;
use plonky2_ecgfp5::curve::curve::WeierstrassPoint;

use crate::{
    length_extraction::{branch::tests::BranchTestCircuit, BranchLengthCircuit},
    MAX_BRANCH_NODE_LEN,
};

use super::{api::utils::compute_metadata_digest, LeafLengthCircuit, PublicInputs};

#[test]
fn prove_and_verify_length_extraction_circuit_for_pudgy() {
    let PudgyState {
        slot,
        length,
        variable_slot,
        dm,
        mut proof,
        key,
        mut pointer,
        ..
    } = PudgyState::validated();

    // setup the circuits

    let setup_leaf = setup_circuit::<_, D, C, LeafLengthCircuit>();
    let setup_branch = setup_circuit::<_, D, C, BranchTestCircuit>();

    // Pudgy leaf

    let node = proof.pop().unwrap();
    let leaf_circuit = LeafLengthCircuit::new(slot, node.clone(), variable_slot);
    let leaf_proof = prove_circuit(&setup_leaf, &leaf_circuit);
    let leaf_pi = PublicInputs::<GFp>::from_slice(&leaf_proof.public_inputs);
    let length = GFp::from_canonical_u32(length);
    let root: Vec<_> = keccak256(&node).pack(Endianness::Little).to_fields();

    assert_eq!(leaf_pi.length(), &length);
    assert_eq!(leaf_pi.root_hash_raw(), &root);
    assert_eq!(leaf_pi.metadata_point(), dm);
    assert_eq!(leaf_pi.mpt_key(), &key);
    assert_eq!(leaf_pi.mpt_key_pointer(), &pointer);

    // Pudgy branches

    let mut pi = leaf_proof.public_inputs;

    while let Some(node) = proof.pop() {
        pointer -= GFp::ONE;

        let branch_circuit = BranchTestCircuit {
            base: BranchLengthCircuit::new(node.clone()),
            pi: &pi,
        };
        let branch_proof = prove_circuit(&setup_branch, &branch_circuit);
        let branch_pi = PublicInputs::<GFp>::from_slice(&branch_proof.public_inputs);
        let root: Vec<_> = keccak256(&node).pack(Endianness::Little).to_fields();
        assert_eq!(branch_pi.length(), &length);
        assert_eq!(branch_pi.root_hash_raw(), &root);
        assert_eq!(branch_pi.metadata_point(), dm);
        assert_eq!(branch_pi.mpt_key(), &key);
        assert_eq!(branch_pi.mpt_key_pointer(), &pointer);

        pi = branch_proof.public_inputs;
    }
}

/// Pudgy state extracted from mainnet live data.
pub struct PudgyState {
    pub eip: EIP1186AccountProofResponse,
    pub depth: usize,
    pub slot: u8,
    pub length: u32,
    pub variable_slot: u8,
    pub dm: WeierstrassPoint,
    pub key: Vec<GFp>,
    pub pointer: GFp,
    pub proof: Vec<Vec<u8>>,
}

impl PudgyState {
    /// Creates a new instance of the pudgy state.
    pub fn new() -> Self {
        let eip = Self::eip1186();
        let proof = eip.storage_proof[0]
            .proof
            .iter()
            .map(|x| x.to_vec())
            .collect::<Vec<_>>();

        let node = proof.last().unwrap();
        let rlp_headers: Vec<Vec<u8>> = rlp::decode_list(node);
        let rlp_nibbles = Nibbles::from_compact(&rlp_headers[0]);
        let pointer = GFp::from_canonical_usize(MAX_KEY_NIBBLE_LEN - 1)
            - GFp::from_canonical_usize(rlp_nibbles.nibbles().len());

        // extracted data
        let depth = 5;
        let slot = 8;
        let length = 8888;
        let key = vec![
            0x0f, 0x03, 0x0f, 0x07, 0x0a, 0x09, 0x0f, 0x0e, 0x03, 0x06, 0x04, 0x0f, 0x0a, 0x0a,
            0x0b, 0x09, 0x03, 0x0b, 0x02, 0x01, 0x06, 0x0d, 0x0a, 0x05, 0x00, 0x0a, 0x03, 0x02,
            0x01, 0x04, 0x01, 0x05, 0x04, 0x0f, 0x02, 0x02, 0x0a, 0x00, 0x0a, 0x02, 0x0b, 0x04,
            0x01, 0x05, 0x0b, 0x02, 0x03, 0x0a, 0x08, 0x04, 0x0c, 0x08, 0x01, 0x06, 0x09, 0x0e,
            0x08, 0x0b, 0x06, 0x03, 0x06, 0x0e, 0x0e, 0x03,
        ]
        .into_iter()
        .map(GFp::from_canonical_u8)
        .collect();

        // arbitrary data
        let variable_slot = 0xfe;
        let dm = compute_metadata_digest(slot, variable_slot).to_weierstrass();

        Self {
            eip,
            depth,
            slot,
            length,
            variable_slot,
            dm,
            proof,
            key,
            pointer,
        }
    }

    /// Creates a validated pudgy state.
    ///
    /// The validation incurs overhead that is not always desirable as it is testing the data
    /// contained within this structure.
    ///
    /// For the trusted version, call [PudgyState::new].
    pub fn validated() -> Self {
        let pudgy = Self::new();

        ProofQuery::verify_storage_proof(&pudgy.eip).unwrap();

        let leaf = pudgy.proof.last().unwrap().to_vec();
        let leaf_list: Vec<Vec<u8>> = rlp::decode_list(&leaf);
        assert_eq!(leaf_list.len(), 2);

        let reversed: Vec<_> = pudgy.proof.iter().rev().cloned().collect();

        visit_proof(&reversed);

        // implement the circuit logic:
        let first_byte = leaf_list[1][0];
        let slice = if first_byte < 0x80 {
            &leaf_list[1][..]
        } else {
            &leaf_list[1][1..]
        }
        .to_vec();

        // reverse big endian EVM to little endian
        let slice = left_pad::<4>(&slice);
        let computed_length = slice.pack(Endianness::Big)[0];
        assert_eq!(computed_length, pudgy.length);

        // extractd from test_pudgy_pinguins_slot
        assert!(pudgy.proof.iter().all(|x| x.len() <= MAX_BRANCH_NODE_LEN));
        assert_eq!(pudgy.proof.len(), pudgy.depth);

        pudgy
    }

    /// Returns the raw EIP1186 response.
    ///
    /// This was extracted via the following script:
    /// ```ignore
    /// let url = mp2_test::eth::get_mainnet_url();
    /// let provider = ethers::providers::Provider::<ethers::providers::Http>::try_from(url)
    ///     .unwrap();
    /// let pidgy_address =
    ///     ethers::abi::Address::from_str("0xBd3531dA5CF5857e7CfAA92426877b022e612cf8").unwrap();
    /// let query = ProofQuery::new_simple_slot(pidgy_address, slot as usize);
    /// let res = query.query_mpt_proof(&provider, None).await.unwrap();
    /// ```
    pub fn eip1186() -> EIP1186AccountProofResponse {
        serde_json::from_str(r#"
{
    "address": "0xbd3531da5cf5857e7cfaa92426877b022e612cf8",
    "balance": "0x0",
    "codeHash": "0x5184c58406e07d654a5e39591c5adf95a8de48e5ea96eec2f4666d84ab248b09",
    "nonce": "0x1",
    "storageHash": "0x6c1cd0ff686809ac6916664836c708fbbcd48f70a6391f851c4efce97626cb2a",
    "accountProof": [
        "0xf90211a0920e0eed755dacbde7c1eb89c9344bef5e927d764ff82fa0c875a6fef289eb88a0d02bf2b4f5bf9d5e8325dd255d871f13c28826fac8c7cc7d4c2f3dc7ff3b2bd5a0ae72178b37b0f7802c7e448d2539596f149807211a81c85f32cec586c6754466a0367cec319f506ede08b8cddc9564833ed361e24f6b8d2e82f49fd372d226f40aa03514007c49a5b40d09dd88f6a0d6e23aad1aa5b4f29d1127d2c852940befac0fa0b2bdfd370c6f8604ee74127d6f045ec1df20485d459469f21ed2ba3fbf71ff17a09d677066da297cf043641b348e0fcd38fc6ad5031808c6fa7dd2250aedd86f65a03a4d50fb3a874145fecf8922abf803372eaa480db061d1641184bcae200b6708a0d719f4f224b58a4a45a9dc8554a087dfe474c15bba3d7ae70a85cfa4245c593fa0c6be1b4ed7d86603b9d48831f68126e30f1a8e0b0b4326392d59728d6e02372aa06ec952463958e787b70d5fc0c98826fc63c393a3417ba05426a7e172fb98b78aa0b03a9d4a5d591b1008321addd68267ed39a9c1c78a8bdf1fb2c9b73ccc1396f7a06f82ea24ddee725a43ffdb6e6b36ec13744fc477a57fb25fb009ba178a92494da02a94843516a03a213fd82b08bdc6a88706bd730ee287f9f304e6d68cdc584968a0ea35f6ac0101ada4faf20911678aa9d8b41da89f23a01ab3f410af2a879a0d76a0f44714ecd590de5bf5672c4b5c42a9aa6bc7dc218f4a87e2e8a85e8ecb49a11780",
        "0xf90211a08d32dd36167d654cac326b7d0c9af6e3c00731390cd47b82e4546ab842111c03a0726308ec277ac8847c9b7c8e920f4b4ea757da36e6c0223f476e4cf62450dabba02e37d97a7bca9dba249576e254723a966f2e917467d8948714ff1a011ba115e5a08175f5901a9b1bff352b71ac89f7c23a18ab5ac5762cdf3d543641c0f0d43284a00f8dd0549cb4db287f8805dd0f63a2085b12baf123d609b8ecf59879ebb493e4a096085424cbec162352009045af83d4dc3d1a68ec775b727397d54e63b5da4d9ba0d9d8686ea78cc63174e990124554885fc877014231e88c1e5dae1c2ad800dcfca01fa482f25711f7fbf16aacc427be6b52808109558358f39d4a8937643beda6fda024b50169dae114fccae0070c9b9bddd72b35c9e5d1780a0a63f3a6f0124d8feba01d988a6a2ff45925c51fdf6eb22b3b24c181c026501483c075d03732ba3f7805a0d307a0e16461209e45315c5ae1af42f0249b6b96791deeae2e1649b2cb738b53a0107f6c809ae70bfb9c19285b1d671199f3ee5dd28988057b50a1c434d6b20880a0af3480ce05c3da6678e2fde8c244105295d8758a53c1655cb5293ea49defe419a07700c94d99d0812863c20dd08f2e8dd7f0e536642e98da7e59692dc585c6dba5a0e3a4df9945e50fdbf6da4fb9327783898a82d52f246c3afc0ac826b4af4cfc36a00a01920302b3d61fa2159e20a83d23756c587ff43e1ac8afaa120281e1d77ac580",
        "0xf90211a063744d9322438996950149a344b6216a5cb18371c5d7fc9e5116103f5254eebba0ca90b9e42460096994b6f4dcafbd86912f0c692b16503208abf393044180aec1a0a73354f2eac70d04f0b80a48c7e29a14a3b2ecfa5f48333f8da477121db78a24a0f30a6166528db153ea1ec5d2490a963fc6c29c3c30380b9f3c7dace8894e9f7ca07d8b2f320ea1612017df3a9038db0e48ceead84a2affb4c7cb354c9df195b49ea0e8b56f9832b432bea3203400553d9ef8175aa9ef26e67290c9845404350c002ba0203020cb0a4ccd73d21b58166e8e92e378797f206a7dfa63e45af15e54b41affa03eee44bdf9511e6de3a488474b74ee3c3a8b420c235b4082da06abfb8d232025a0520e019630d2d8dd45843caf28b61948fafc535c7aa407429590f60a11cd7830a0bb34386c71fe08edf1889459e5006bc4655d5cbc2498587f292342abc2a887bba070ec5ee8c2fbc2b9c3ed13a8bcbe943f95b1f5540f231199cdf7da5c0851aec0a06eaaf7932f7ba33461ba79fe942de00e68ff7728cc458b5135b37cb55329c083a0f15b05526920beeec3738655325f10a0fecb5ffef9521a7c2d31f5a1ecfd27c3a043da0de1935e770f368bad3d07ea03fcfd05b6001c63f66cdea7f07dfacbddd3a0474aa79d3ebd5bbee138e521e53a9f157542adef04dc45520da0215247893588a0daaf9f19f38529917c3364ef9c4f6a7efe7d1a858e02f199be4b8171a4b7ba5680",
        "0xf90211a0144f91b30a8ff8e3e7913589f9ab990fb5e8a99a33c45f9ec61c6c611b2b3024a070c814ed2d26deca619d631bf50592558ad4d3a7315e81fac9e6052fce48a616a06be64106ce3330dc9ede5cb1dc81006db7530fc042a739f4a35c387096d1f92aa09356bd7946ed32bc94e8800b6e15a6ab46246a4727c1a653ba05ab842c6b8ed8a09089edcb69d58999c30ce32c8532914a4941f5bd2036fb486b0c68c146774abca0a6061de55f457c846ccb1bc4ab1c55a0000228162d5a262b98af8030c32da7eaa08d537ed95608216297932871c8353fbd93a4f8b6de362374c5a91cb0c16fa8e6a04d3578d6d8b4575d791b2098aff77d1ba7450d1a7fd359fe96bbeabef5fe555aa0f8d4ae972d150f4648559fc873c506ee942fd58c7af66ac5fc58db11392a0585a0eac5413bd4ae9d3b03e0ec392dbaf9aca1e13254f19b23e47645cfcc58c91cbba035921bb77e55401d961b5069d9a8c8283f78f32576138e12f3c2aee4aee384a6a0ae3a1172f4898de19ccd0f8f03852972a5f9383cf3d5d0f2ae66aeea8faf0350a0ccdfaa5b60d41e01a6c2a4ab7edab7bf17b298944e3bf0e95596038eae07834ca091e55d5c98f57e15785585f1e69e62fa87bc0b6acd12efa46bd02538e2c0ec0da0b5fe2ddce900f2de90e9b26bd64497334720f75f843967c344c317c56c856868a0754f6c1ef2ace70e7db213b56002de56c457fb71cffe171c5dd1b15431bd616c80",
        "0xf90211a0ec53c61895012f398b78101bbbca3d902c1c89ef419d49777b7a320162131cbaa0b53a3ebe7b143851e789fbad5ca89657131b198a986b9e00027bbcf77127bdaba0372030503101498c86e6089e244a9ede0fa4514d9582c48772927e2aff790436a0ec5c13796688e30c0196171f56da75ac07c0947ba69844bd653581890257723ea09c945a4e4947d8873d6f9df0e11199c1d353dd30e5d4529714f2f4b8d2d0eff4a0cf778cd29926ee357cfdcbfef5e3666dd8f5b8c4feed7c92b65ba6f46cb907d4a0912ae04872e8d886fc624b0ee188b41d7f7a37fcc38c49bc329b0620884f5f5aa01aec2af4303bd4176d3f6d64346b27fc53dcc97304d6feeb781cbf0f14de576ba07c8182ade5de6a56a9fb24059cdaca9609d91fff58cae0ec01a8772aefd02376a0cb41c39875f3bdd00e31adb064c7a9794b4f599b6b3d5791acd8bf7756e3c73ea0429eea83e4ea537b75926641829e1929352c8968e86ab2389095ce00bcc02ef0a01b756bda18614c6d0aa5f81cd031bc1192150aa0e7b47c63fa194133106a34cca0587b3c86d0f7daa1020b42e768dad969223b314c79d8687c7614f671663a2dafa03e359b6b105a287d4af0e8e2c3dc41634c3c6782d10423747cf6f6e4352f73f7a04fa4ca146e5cf8eeb2b75f595f730e86520a29fef4ec61bb01f70272863bbd63a0ec70151b8b31e8c4966708af23791e54f72e7795e9ce407c816e4d6d872af66d80",
        "0xf90211a022e2d10f7771dc3d4e621e01a465f5ef2de2cca7e6e17391e2d829fe0b724ec4a07ded508b3ade836fa5000e892850cb7fb1173cb3652c037e4b95bdaa8b580096a0c8fb7f078f5d48aabfdb287bbbafd37d21292a8b66cff66d03342f019bb41b07a0581779be6e8b54b0f9248eeabea105a01fad072e756eca3fa5a1c4f297c3ffeba0139613803cf36538a6d7dcb6e9ded65f68887ab6dd68392d37bee4c529ad5bfca02c6a95558998d2086b0414599b16179bf6a5175a070106cb9a74fced88b53a5fa0d11915a9503822b50374f3f21da679a3608d50aeeca679fd2f99793b4e9be07da0cd22c4d91055e7c07e01ffb0d576449e2fcaa071a4421ae70e694da67567344ea0eaae6003faf2791cd3974da35d9bf66441c50ec09565e8c2df39566da0e94aeea05d2dd31de727f86c8c047fdfe2619f38ce8e7fa849381c60eedf398b08aa8a44a0eaabae55702613813f0a75dbfc19a2f056efd4ef1f489e0c5a42868d5653615aa0e87189d0a3d65c5a43c75c34f1182262dd2f6344cab7b526e3ab5702492cf8b3a04fb44eca5d6064b1a92a94af01ac4625d46f26ecd885d8a869d941790f5b52b9a0ee3b45d8fb82a9c9a8a78f532697d413db541611a6eb07c6c39c14e01a92adb2a064d95b37f5aba24b2832b6638a0f37f8b3e6b5139b1739d4a4ce2e4252468247a0c3c9f9b880ba01d667e0e833546755e685451bdc11124a8278e85c4742bf2a6880",
        "0xf9017180a0809cf82449b7aef1d3da62a288d3be956b438362342b0b2f7d3788d833bd9bb1a078d9a75872dde899c3e8bd8e61d7a151e95c0868c0d49adf9847c3199ef771f1a055b438c12e5207c706d9bce9de955538e4a4927edd9af9581f50e416593a8c29a03511d8d0eb3754d741515f1d13d34501339d6c157ad37de0a3b8bcd0214c19df80a0fbee4cf71c14709b9978cc77cfcd6040c7c588e51eaf1015629581009318c18180a0c1e93e4079561c659b5b511228c879f409c89435e26d599d6ae5d19f9f38f098a07a6e642144b988bfdf80d0a26e83d046ab8335c1d17a02eacb915de18ec78d0780a0d0f59c367bf01ff716f8f914eb30b3c67773bfd059aec65b11e24827fa49d43d80a0f3d7c58305eaabd2c31ad2c0793d90d9505b47042af520e0767db1c6a98308f6a0c6aaf92dc867d76c5ca3153a4cd9e0fe313e4145e7ea0f2ced592a0f531a00cca072ae87d585c350c2a87c97728ebc81306a100cd014b6be1a5d6a28e1bbf91fb280",
        "0xf851a0e51f538dd3163e214e48d19066c2058a2ea0f422490882ed8cbbe86fc7f267de80808080808080808080a09dbd48822d65e861aa861d02bc5b06fda4c8030be9c530beed182ef3af3ad24e8080808080",
        "0xf8669d205b3effba685d535779bddd89290c63917c57af9d5519f29dff437163b846f8440180a06c1cd0ff686809ac6916664836c708fbbcd48f70a6391f851c4efce97626cb2aa05184c58406e07d654a5e39591c5adf95a8de48e5ea96eec2f4666d84ab248b09"
    ],
    "storageProof": [
        {
            "key": "0x8",
            "proof": [
                "0xf90211a0ddc310188778413757d2e208cb1ce430300b595183b68082313a64aa34334ba0a05d66028b70b854a298d5ca3914c7ed0c9e83cb08e03cc59531071cd199df1bcda0c582171adf3bd7dbdb200d555b3b28fc48d018be912612c74a37783157341058a0672bae6c4691ea6cd9cc5962d5eb508b3c8804760e98aad47ef1dc67284a578ea06935ba07c57bb413df53d7b72e00b951123fbc7ce877e551bd3b95129bf313cea03bca4e966b03dea6986fd56046393dd90d957f5cda5d4a6b4e9ec2a82604abfea05d7d260d72b82f5558e538c1ba8f54e51c1f85bfea136bf0d379f80a7064506ba00495c5094c938b55c576054c79e710685c099fe4d0d7da07a1f6a1ed3372b4afa0ea882b96da37bb72a290711e5b2a2a42edc0db9cf341ba9b4d0c2d638c3e8519a0d0e2e14e7295e234a43a7a52e81dd1644954ee619077e9d9e4b61c6c0f094bd0a024fec05d48a3ad7904a193041f4c5aaf791342e6807b8e7333ce72daee3732dea043c8cd3c011ab31a6486a98de89855f2e1e5760160c15716b84191cdc3f8f776a0a988b370d7d7553f93d7f719aabb241def5c5230e05dbb583c2ce02d559358f9a0d648bcec95945acf57f88d12977d42dd587334aa667767bd11080783736dfe2da0719d9662f321cd2a681e1e37b80652fac15c6d99fa0cdc9f1ff5e3f009371841a0852c59e9fa23a3550086a9687454b095c04bb1a505c349616a38fed590d2915780",
                "0xf90211a0b57ea04fd4392c535045f94637da5ac62dfb12bab4b96bbe43899a87e886e5d6a0515f2eef9a03373c8ffc7b5c6468225d6855072f5d1c6294a21156c319faeb24a067f4027013028d9bfa9ac67d0e9150d6f214c154052326c9012f474d4a6d9cc8a001a90ac360073b8784ede20c64c33cd957f9d212932937b7f67e55998bf63248a08d6394c1aaff0902f5accc8ee5852848c43383084baab7b18a5499013c5f60c7a01ba2ce61bafcb854fff5a53c74af9feddd0e6b0d8baa78031f31cf67562252cea01ed3256e0a6d6e035380d4415672a9284b36804b0719feb2fba441edaf98c584a0aee3d4e1765dfc4ca3cec2679da95807c8ba2c78a499f6bd43fd4503ee20c1a2a0fb1e56a139dd24118d8a548cecaccf67bd5c65758b924a994a8de7ee84a17577a092c6b400cba792e3152aca42ee78e2a9571ec0e6dac65c171ffd852945f445baa04709e688e2d1f40277497f0e8d01987dfbecdfc81f5b1eaf72bef08e5864e3a4a08bcfd1e4df1bed22a8f59d630d3ac2a5829c2192db753b8b36175437394d2568a0b65649b26d81a09239dc4aa4523bf0b8eb06478a1bccfca5652c97eeebfa7ec2a06b64c995ad5af13dba0088eb5740f1d22002e6ad43fa4d83b249d48b9af4996ea07d162fe0b6820ac24efbba7778224d360972ba357cb864adddbf43ef84a9bbf0a0998d622b3e4c73f14411a545abff64a5c4bf16bc1db470269ef169583ab82be380",
                "0xf90211a036f85b4facbe3a05efde9edcc58dff9d7730d3aae0f19c8825e9581980b8a08da043551ce700e6a3b96d34bf5c81665c0234c010ba34fa5ba6e6e4716248720eb1a0ccfcb6fce13b971d78debcbbfa77c95293a26c3029a420093f5ed5fbebf54346a091d8f6bde58f435688ba5014439638338f73bf06d11998cb4db8a74d0140828ea0db4df126a24845243055ac24211d2a3863a1181dc85f61227291a3360005a143a07bab1920f0cb45986b40c41f036f2f214d387b439a8ee6b87a3289d1f4fbabcfa09ef786a5d051e548964a48d4b6e607900a6e0a45a96c9c6d5f402f9c342d1247a0b6a2a375821a9dd2521d5d538462c06b2e4f1adb9f19ac388381ed2de8f85840a0ccff3ffd75a34a4d4d1b23dbfb172741f472c77ed96ac0397ea31c5f89457e33a053f85c52eaadb113463fbdbeb630c3b3ceb7dcd5b085594802e107ce676a3f3da01591bf3bc3f9108e7c5688b359b84dd1c091bdd78d9f310bbb16e3c08a277190a0bada92bba4fee6d4fcb6e350371236a566a5fb79200d27be3bca5c2817e9a024a027b4fda4369300815f29c3971a48e5979d542c561b26475c956b95a6ef82569ba006246a53804269ce36b8e74861ea0934a3c1e4a79f11df4c671a9e149ba42263a0f57e4b9ca84c42a0123619bc22ac8d3d55be66a3dcc5409b589245e0cbfa8ca5a0f70e6108e4775d34f22888b8a1ab3cb08fa5e64a823a7efce182ea7bddc334ae80",
                "0xf901b1a079273a5dfdf8eb4630b712c3b067ef81660832987289e0edc67a6eef615c645aa031b112e46db8cc1822ff0df9d56f996ba9b8726cbc44db6e8afda5f8538846c7a04d1d6630c3ed49be1509b9cfea0a61c6cc793aa90d3b95cc08707bec3286bd3ba0c90f1dcfaf20bcdf7c158971233561bce16e17ccf5b0e55099c24766ebc4e7eba09bd3af807dfeea4c4e35099a180d5587eabe6289b9b977a447d5749b88d2a20f8080a0a2bb20282d398cdfcbbe375171659d33bd732108affdce6db775699f2096f7a7a0de9621d0429154056403f262815c333431fc3e018cc3ac67f8d09a7f69e638b7a07cd2c617c9e647d7116f334a841a6eadb5fed75347bf6f15b2ef6d10c41abecba0ca3b121f9b3ed0a323ef7ba3156371bb4b8c7d6211f16156c4009e5c6b6b619ba08a7a3688b54e45dca802d617e09dfbe4e67791f5ff7b46e8366a05d9bdfbecc8a0df74f17984afc290b32a2e2f32924cf69b8129a0f4caab33ff33b76cde02edf0a0740f868098cf274b11bdf5971cf479e53b09e2238494396abaf84b7fdd9e4d1ba001b9f28c8eb0b3f5932605ac56bfec4e4887c604c4488e476f69eab24c90f81e8080",
                "0xe49f20a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee3838222b8"
            ],
            "value": "0x22b8"
        }
    ]
}
        "#).unwrap()
    }
}
