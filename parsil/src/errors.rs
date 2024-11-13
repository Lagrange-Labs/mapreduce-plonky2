use sqlparser::ast::{BinaryOperator, UnaryOperator};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("query projection must not mix aggregates and scalars")]
    MixedQuery,

    #[error("qery body should be a SELECT statement")]
    NotASelect,

    #[error("`{0}`: unsupported operator")]
    UnsupportedUnaryOperator(UnaryOperator),

    #[error("`{0}`: unsupported operator")]
    UnsupportedBinaryOperator(BinaryOperator),

    #[error("`{0}`: unknown function")]
    UnknownFunction(String),

    #[error("`{0}`: expected {1} argument, found {2}")]
    InvalidArity(String, usize, usize),

    #[error("`{0}`: unexpected argument type")]
    InvalidFunctionArgument(String),

    #[error("`{0}`: unknown placeholder")]
    UnknownPlaceholder(String),

    #[error("`{0}` is not used")]
    MissingPlaceholder(String),

    #[error("`{0}`: unsupported immediate value")]
    UnsupportedImmediateValue(String),

    #[error("`{0}`: nested selects are not supported")]
    NestedSelect(String),

    #[error("`{0}`: set operations are not supported")]
    SetOperation(String),

    #[error("`{0}`: mutable queries are not supported")]
    MutableQueries(String),

    #[error("{0} unsupported")]
    UnsupportedFeature(String),

    #[error("`{0}`: unsupported jointure")]
    UnsupportedJointure(String),

    #[error("`{0}`: non-standard SQL")]
    NonStandardSql(String),

    #[error("`{0}`: ORDER BY only supports up to {1} criterions")]
    OrderByArity(String, usize),

    #[error(
        "ORDER BY criterions must be present in the SELECT expressions; `{0}` not found in SELECT"
    )]
    SpecialOrderBy(String),

    #[error("`{0}`: compounded table names unsupported")]
    CompoundTableName(String),

    #[error("`{0}`: reserved identifier")]
    ReservedIdentifier(String),

    #[error("unable to convert `{0}` to a U256")]
    InvalidInteger(String),

    #[error("NULL-related ordering specifiers unsupported")]
    NullRelatedOrdering,

    #[error("Clause `{0}` value should be set in the approporiate parameter at execution time")]
    UseInvocationParameter(String),
}
