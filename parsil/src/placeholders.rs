//! This module handles the validation of adequate use of placeholders within a
//! [`Query`].
use std::collections::HashSet;

use anyhow::*;
use sqlparser::ast::{Expr, Query, Value};
use verifiable_db::query::computational_hash_ids::PlaceholderIdentifier;

use crate::{
    errors::ValidationError,
    symbols::ContextProvider,
    utils::ParsilSettings,
    visitor::{AstVisitor, Visit},
};

pub struct PlaceholderValidator<'a, C: ContextProvider> {
    /// Parsil settings provided by the user
    settings: &'a ParsilSettings<C>,
    /// Stores at i whether free-standing placeholder $(i+1) has been met
    visited: Vec<bool>,
    /// The largest free-standing placeholder met; 0 if none
    current_max_freestanding: usize,
}
impl<'a, C: ContextProvider> PlaceholderValidator<'a, C> {
    /// Instantiate a new [`PlaceholderValidator`] from the given settings.
    fn new(settings: &'a ParsilSettings<C>) -> Self {
        Self {
            settings,
            visited: vec![false; settings.placeholders.max_free_placeholders],
            current_max_freestanding: 0,
        }
    }

    /// Ensure that the given placeholder is valid, and update the validator
    /// internal state accordingly.
    fn resolve(&mut self, name: &str) -> Result<()> {
        if let PlaceholderIdentifier::Generic(i) =
            self.settings.placeholders.resolve_placeholder(name)?
        {
            self.visited[i - 1] = true;
            self.current_max_freestanding = self.current_max_freestanding.max(i);
        }
        Ok(())
    }

    /// Ensure that all the placeholders have been used and that the number of
    /// parameters matches the number of placeholders, and return the largest
    /// one found.
    fn ensured_used(&self) -> Result<usize> {
        for i in 0..self.current_max_freestanding {
            ensure!(
                self.visited[i],
                ValidationError::MissingPlaceholder(format!("${}", i + 1))
            );
        }
        if let Some(parameters_count) = self.settings.placeholders.parameters_count.get() {
            ensure!(
                *parameters_count == self.current_max_freestanding,
                ValidationError::TooManyParameters {
                    expected: self.current_max_freestanding,
                    got: *parameters_count,
                }
            );
        }
        Ok(self.current_max_freestanding)
    }

    /// Return a [`HashSet`] containing all the numeric placeholders found in
    /// the query, without any guarantee of contiguity.
    fn gather_placeholders(&self) -> Result<HashSet<usize>> {
        Ok(self
            .visited
            .iter()
            .enumerate()
            // self.visited starts at 0, placeholders start a 1
            .filter_map(|(i, used)| if *used { Some(i + 1) } else { None })
            .collect())
    }
}

impl<C: ContextProvider> AstVisitor for PlaceholderValidator<'_, C> {
    type Error = anyhow::Error;

    fn pre_expr(&mut self, expr: &Expr) -> anyhow::Result<()> {
        if let Expr::Value(Value::Placeholder(name)) = expr {
            self.resolve(name)?;
        }
        Ok(())
    }
}

/// Instantiate a [`PlaceholderValidator`], then run ot on the given query.
/// Return the number of used free-standing placeholders if successful, or
/// an error if the placeholder use is inappropriate.
pub fn validate<C: ContextProvider>(settings: &ParsilSettings<C>, query: &Query) -> Result<usize> {
    let mut validator = PlaceholderValidator::new(settings);
    query.visit(&mut validator)?;
    validator.ensured_used()
}

/// Instantiate a [`PlaceholderValidator`], then run ot on the given query.
/// Return the number of used free-standing placeholders if successful, or
/// an error if the placeholder use is inappropriate.
pub fn gather_placeholders<C: ContextProvider>(
    settings: &ParsilSettings<C>,
    query: &Query,
) -> Result<HashSet<usize>> {
    let mut validator = PlaceholderValidator::new(settings);
    query.visit(&mut validator)?;
    validator.gather_placeholders()
}
