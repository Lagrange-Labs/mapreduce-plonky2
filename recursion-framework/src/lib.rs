#![warn(missing_docs)]
#![feature(generic_const_exprs)]


//! ToDo

/// Internal module that contains the core data structures and gadgets for the universal verifier
pub(crate) mod universal_verifier_gadget;
/// This module contains data structures useful to instantiate circuits that either employ the universal verifier 
/// or whose proofs needs to be verified by a circuit employing the universal verifier
pub mod circuit_builder;
/// This module contains data structures that allow to generate proofs for a set of circuits that 
/// either employ the universal verifier or whose proofs needs to be verified by a circuit employing 
/// the universal verifier
pub mod framework;
/// This module contains a variant of the framework that simplifies testing and benchmakring the circuits based on
/// the universal verifier and written employing the data structures and interfaces provided in the `framework` 
/// module
pub mod framework_testing;

