#![cfg(feature = "testutils")]

use ed25519_dalek::Keypair;
use rand::thread_rng;
use soroban_auth::{
    check_auth, Ed25519Signature, Identifier, NonceAuth, Signature, SignaturePayload,
    SignaturePayloadV0,
};
use soroban_sdk::testutils::ed25519::Sign;
use soroban_sdk::{contractimpl, contracttype, symbol, vec, BigInt, BytesN, Env, IntoVal, Vec};

#[contracttype]
pub enum DataKey {
    Nonce(Vec<Identifier>),
}

fn read_nonce(e: &Env, ids: Vec<Identifier>) -> BigInt {
    let key = DataKey::Nonce(ids);
    e.contract_data()
        .get(key)
        .unwrap_or_else(|| Ok(BigInt::zero(e)))
        .unwrap()
}

struct NonceForSignature(Vec<Signature>);

impl NonceAuth for NonceForSignature {
    fn read_nonce(&self, e: &Env) -> BigInt {
        //TODO: key is generated twice
        //TODO: figure out how to use collect() here
        let mut ids = Vec::<Identifier>::new(e);
        self.0
            .iter()
            .for_each(|s| ids.push_back(s.unwrap().get_identifier(e)));
        read_nonce(e, ids)
    }

    fn read_and_consume_nonce(&self, e: &Env) -> BigInt {
        let mut ids = Vec::<Identifier>::new(e);
        self.0
            .iter()
            .for_each(|s| ids.push_back(s.unwrap().get_identifier(e)));

        let key = DataKey::Nonce(ids);
        let nonce = Self::read_nonce(&self, e);
        e.contract_data().set(key, &nonce + 1);
        nonce
    }

    fn signatures(&self) -> &Vec<Signature> {
        &self.0
    }
}

pub struct TestContract;

#[contractimpl]
impl TestContract {
    pub fn verify_sig(e: Env, sig: Signature, nonce: BigInt) {
        let auth_id = sig.get_identifier(&e);

        check_auth(
            &e,
            &NonceForSignature(vec![&e, sig]),
            nonce.clone(),
            symbol!("verify_sig"),
            (&auth_id, nonce).into_val(&e),
        );
    }

    pub fn nonce(e: Env, ids: Vec<Identifier>) -> BigInt {
        read_nonce(&e, ids)
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
    env.register_contract(&contract_id, TestContract);
    let client = TestContractClient::new(&env, contract_id);

    let kp = generate_keypair();
    let id = make_identifier(&env, &kp);
    let nonce = client.nonce(&vec![&env, id.clone()]);

    let msg = SignaturePayload::V0(SignaturePayloadV0 {
        function: symbol!("verify_sig"),
        contract: BytesN::from_array(&env, &[0; 32]),
        context: vec![&env],
        network: env.ledger().network_passphrase(),
        args: (&id, &nonce).into_val(&env),
    });
    let sig = Signature::Ed25519(Ed25519Signature {
        public_key: BytesN::from_array(&env, &kp.public.to_bytes()),
        signature: kp.sign(msg).unwrap().into_val(&env),
    });

    client.verify_sig(&sig, &nonce);
}
