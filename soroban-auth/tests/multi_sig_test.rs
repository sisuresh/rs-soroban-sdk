#![cfg(feature = "testutils")]

use ed25519_dalek::Keypair;
use rand::thread_rng;
use soroban_auth::{
    check_auth, Ed25519Signature, Identifier, Signature, SignaturePayload, SignaturePayloadV0,
};
use soroban_sdk::testutils::ed25519::Sign;
use soroban_sdk::{contractimpl, contracttype, symbol, vec, BigInt, BytesN, Env, IntoVal, Vec};

#[contracttype]
pub enum DataKey {
    Nonce(Vec<Identifier>),
}

fn read_nonce(e: &Env, ids: &Vec<Identifier>) -> BigInt {
    let key = DataKey::Nonce(ids.clone());
    e.contract_data()
        .get(key)
        .unwrap_or_else(|| Ok(BigInt::zero(e)))
        .unwrap()
}

fn verify_and_consume_nonce(e: &Env, ids: &Vec<Identifier>, expected_nonce: &BigInt) {
    // This contract doesn't special case the nonce for Signature::Contract like
    // SingleSigContract

    let key = DataKey::Nonce(ids.clone());
    let nonce = read_nonce(e, ids);

    if nonce != expected_nonce {
        panic!("incorrect nonce")
    }
    e.contract_data().set(key, &nonce + 1);
}

pub struct MultiSigContract;

#[contractimpl]
impl MultiSigContract {
    pub fn verify_sig(e: Env, sigs: Vec<Signature>, nonce: BigInt) {
        let mut ids = Vec::<Identifier>::new(&e);
        //TODO: figure out how to use collect() here
        sigs.iter()
            .for_each(|s| ids.push_back(s.unwrap().get_identifier(&e)));

        verify_and_consume_nonce(&e, &ids, &nonce);

        check_auth(&e, &sigs, symbol!("verify_sig"), (&ids, nonce).into_val(&e));
    }

    pub fn nonce(e: Env, ids: Vec<Identifier>) -> BigInt {
        read_nonce(&e, &ids)
    }
}

fn generate_keypair() -> Keypair {
    Keypair::generate(&mut thread_rng())
}

fn make_identifier(e: &Env, kp: &Keypair) -> Identifier {
    Identifier::Ed25519(kp.public.to_bytes().into_val(e))
}

#[test]
fn test() {
    let env = Env::default();
    let contract_id = BytesN::from_array(&env, &[0; 32]);
    env.register_contract(&contract_id, MultiSigContract);
    let client = MultiSigContractClient::new(&env, contract_id);

    let kp1 = generate_keypair();
    let id1 = make_identifier(&env, &kp1);

    let kp2 = generate_keypair();
    let id2 = make_identifier(&env, &kp2);

    let id_vec = vec![&env, id1, id2];

    let nonce = client.nonce(&id_vec);

    let msg = SignaturePayload::V0(SignaturePayloadV0 {
        function: symbol!("verify_sig"),
        contract: BytesN::from_array(&env, &[0; 32]),
        network: env.ledger().network_passphrase(),
        args: (&id_vec, &nonce).into_val(&env),
    });

    let sig1 = Signature::Ed25519(Ed25519Signature {
        public_key: BytesN::from_array(&env, &kp1.public.to_bytes()),
        signature: kp1.sign(&msg).unwrap().into_val(&env),
    });
    let sig2 = Signature::Ed25519(Ed25519Signature {
        public_key: BytesN::from_array(&env, &kp2.public.to_bytes()),
        signature: kp2.sign(&msg).unwrap().into_val(&env),
    });

    client.verify_sig(&vec![&env, sig1, sig2], &nonce);
}
