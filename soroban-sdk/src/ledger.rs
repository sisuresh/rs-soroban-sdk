use crate::{
    env::internal::{self, RawValConvertible},
    Bytes, Env,
};

#[derive(Clone)]
pub struct Ledger(Env);

impl Ledger {
    #[inline(always)]
    pub(crate) fn env(&self) -> &Env {
        &self.0
    }

    #[inline(always)]
    pub(crate) fn new(env: &Env) -> Ledger {
        Ledger(env.clone())
    }

    /// returns the current ledger version
    pub fn get_ledger_version(&self) -> u32 {
        let env = self.env();
        let val = internal::Env::get_ledger_version(env);
        unsafe { u32::unchecked_from_val(val) }
    }

    /// Returns the sequence number of the ledger.
    ///
    /// The sequence number is a unique number for each ledger
    /// that is sequential, incremented by one for each new ledger.
    pub fn sequence(&self) -> u32 {
        let env = self.env();
        let val = internal::Env::get_ledger_sequence(env);
        unsafe { u32::unchecked_from_val(val) }
    }

    /// Returns a unix timestamp for when the ledger was closed.
    ///
    /// The timestamp is the number of seconds, excluding leap seconds,
    /// that have elapsed since unix epoch. Unix epoch is January 1st, 1970,
    /// at 00:00:00 UTC.
    pub fn timestamp(&self) -> u64 {
        let env = self.env();
        let obj = internal::Env::get_ledger_timestamp(env);
        internal::Env::obj_to_u64(env, obj)
    }

    /// Returns the network identifier.
    ///
    /// Returns for the Public Network:
    /// > Public Global Stellar Network ; September 2015
    ///
    /// Returns for the Test Network:
    /// > Test SDF Network ; September 2015
    pub fn network_id(&self) -> Bytes {
        let env = self.env();
        let bin_obj = internal::Env::get_ledger_network_id(env);
        unsafe { Bytes::unchecked_new(bin_obj.in_env(env)) }
    }
}
