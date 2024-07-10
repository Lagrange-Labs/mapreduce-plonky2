pub mod public_inputs;
pub mod universal_query_circuit;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Set of constant identifiers employed in the
/// computational hash, which is a compact representation
/// of the query being proven by the query circuits
pub enum ComputationalHashIdentifiers {
    AddOp,
    SubOp,
    MulOp,
    DivOp,
    ModOp,
    LessThanOp,
    EqOp,
    NeOp,
    GreaterThanOp,
    LessThanOrEqOp,
    GreaterThanOrEqOp,
    AndOp,
    OrOp,
    NotOp,
    XorOp,
}
