#![warn(missing_docs)]
#![feature(generic_const_exprs)]


//! ToDo

pub(crate) mod universal_verifier_gadget;
/// This module contains data structures useful to instantiate circuits that either employ the universal verifier 
/// or whose proofs needs to be verified by a circuit employing the universal verifier
pub mod circuit_builder;
/// This module contains data structures that allow to generate proofs for a set of circuits that 
/// either employ the universal verifier or whose proofs needs to be verified by a circuit employing 
/// the universal verifier
pub mod framework;

