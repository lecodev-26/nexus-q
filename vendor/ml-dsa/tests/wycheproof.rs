//! Test against the Wycheproof test vectors.

// Implementation is based in part on `rsa` which is in turn based on Graviola.

use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, Seed, Signature, SigningKey, VerifyingKey};
use serde::Deserialize;
use signature::{SignatureEncoding, Signer, Verifier};
use std::fs::File;

#[derive(Deserialize, Debug)]
struct TestFile {
    #[serde(rename(deserialize = "testGroups"))]
    groups: Vec<TestGroup>,
    header: Vec<String>,
    algorithm: String,
}

#[derive(Deserialize, Debug)]
struct TestGroup {
    #[allow(dead_code)]
    #[serde(rename(deserialize = "type"))]
    type_: String,

    #[serde(default, rename(deserialize = "privateSeed"), with = "hex::serde")]
    private_seed: Vec<u8>,

    #[serde(
        default,
        rename(deserialize = "publicKey"),
        deserialize_with = "deserialize_hex_or_null"
    )]
    #[allow(dead_code)]
    public_key: Vec<u8>,

    tests: Vec<Test>,
}

fn deserialize_hex_or_null<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|value| hex::decode(value).map_err(serde::de::Error::custom))
        .transpose()
        .map(Option::unwrap_or_default)
}

#[derive(Deserialize, Debug)]
struct Test {
    #[serde(rename(deserialize = "tcId"))]
    id: usize,
    comment: String,
    #[serde(default, with = "hex::serde")]
    msg: Vec<u8>,
    #[serde(default)]
    mu: Option<String>,
    #[serde(default, with = "hex::serde")]
    ctx: Vec<u8>,
    #[serde(with = "hex::serde")]
    sig: Vec<u8>,
    result: ExpectedResult,
}

#[derive(Copy, Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ExpectedResult {
    Valid,
    Invalid,
    Acceptable,
}

macro_rules! load_json_file {
    ($json_file:expr) => {{
        let path = format!("../thirdparty/wycheproof/testvectors_v1/{}", $json_file);
        let data_file = File::open(&path)
            .expect("failed to open data file (try running `git submodule update --init`)");

        println!("Loading file: {path}");

        let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");
        println!("{}:\n{}\n", tests.algorithm, tests.header.join(""));
        tests
    }};
}

macro_rules! mldsa_sign_seed_test {
    ($name:ident, $json_file:expr, $params:ident) => {
        #[test]
        fn $name() {
            let tests = load_json_file!($json_file);

            for group in tests.groups {
                let Ok(seed) = Seed::try_from(group.private_seed.as_slice()) else {
                    assert!(
                        group
                            .tests
                            .iter()
                            .all(|test| test.result == ExpectedResult::Invalid),
                        "invalid seed length must only be used by invalid test vectors"
                    );
                    continue;
                };
                let sk = SigningKey::<$params>::from_seed(&seed);

                for test in &group.tests {
                    println!("Test #{}: {} ({:?})", test.id, &test.comment, &test.result);

                    if let Some(mu) = &test.mu {
                        let mu = hex::decode(mu).expect("valid hexadecimal mu");
                        let mu = mu.as_slice().try_into().expect("ML-DSA mu is 64 bytes");
                        let sig = sk.expanded_key().sign_mu_deterministic(&mu);
                        assert_eq!(&*sig.to_bytes(), test.sig.as_slice());
                    } else if test.ctx.is_empty() {
                        let sig = sk.sign(&test.msg);
                        assert_eq!(&*sig.to_bytes(), test.sig.as_slice());
                    } else {
                        let result = sk.expanded_key().sign_deterministic(&test.msg, &test.ctx);

                        match test.result {
                            ExpectedResult::Valid => {
                                assert_eq!(
                                    &*result.expect("should be valid").to_bytes(),
                                    test.sig.as_slice()
                                )
                            }
                            ExpectedResult::Invalid => {
                                assert!(result.is_err())
                            }
                            other => todo!("{:?}", other),
                        }
                    }
                }
            }
        }
    };
}

macro_rules! mldsa_verify_test {
    ($name:ident, $json_file:expr, $params:ident) => {
        #[test]
        fn $name() {
            let tests = load_json_file!($json_file);

            for group in &tests.groups {
                if let Ok(encoded_vk) = group.public_key.as_slice().try_into() {
                    let vk = VerifyingKey::<MlDsa44>::decode(&encoded_vk);
                    for test in &group.tests {
                        println!("Test #{}: {} ({:?})", test.id, &test.comment, &test.result);

                        if let Some(sig) = test
                            .sig
                            .as_slice()
                            .try_into()
                            .ok()
                            .and_then(|sig| Signature::<MlDsa44>::decode(&sig))
                        {
                            if test.ctx.is_empty() {
                                let result = vk.verify(&test.msg, &sig);

                                match test.result {
                                    ExpectedResult::Valid => assert!(result.is_ok()),
                                    ExpectedResult::Invalid => assert!(result.is_err()),
                                    other => todo!("{:?}", other),
                                }
                            } else {
                                // TODO(test) contexts
                            }
                        } else {
                            println!("error decoding signature (length: {})", test.sig.len(),);
                            assert_eq!(test.result, ExpectedResult::Invalid);
                        }
                    }
                }
            }
        }
    };
}

mldsa_sign_seed_test!(
    mldsa_44_sign_seed_test,
    "mldsa_44_sign_seed_test.json",
    MlDsa44
);
mldsa_sign_seed_test!(
    mldsa_65_sign_seed_test,
    "mldsa_65_sign_seed_test.json",
    MlDsa65
);
mldsa_sign_seed_test!(
    mldsa_87_sign_seed_test,
    "mldsa_87_sign_seed_test.json",
    MlDsa87
);
mldsa_verify_test!(mldsa_44_verify_test, "mldsa_44_verify_test.json", MlDsa44);
mldsa_verify_test!(mldsa_65_verify_test, "mldsa_65_verify_test.json", MlDsa65);
mldsa_verify_test!(mldsa_87_verify_test, "mldsa_87_verify_test.json", MlDsa87);
