use anyhow::*;
use log::debug;
use sqlparser::ast::{
    Expr, GroupByExpr, Ident, Query, Select, SelectItem, SetExpr, Subscript, TableFactor,
};
use std::collections::HashSet;

use crate::symbols::ContextProvider;

enum TableSymbols {
    Normal(String, HashSet<String>),
    Alias {
        alias_name: String,
        real_name: String,
        columns: HashSet<String>,
    },
}
impl TableSymbols {
    fn resolve(&self, symbol: &str) -> Option<(String, String)> {
        match self {
            TableSymbols::Normal(me, columns) => {
                columns.get(symbol).map(|s| (me.clone(), s.to_owned()))
            }
            TableSymbols::Alias {
                real_name, columns, ..
            } => columns
                .get(symbol)
                .map(|s| (real_name.clone(), s.to_owned())),
        }
    }

    fn resolve_qualified(&self, table: &str, symbol: &str) -> Option<(String, String)> {
        match self {
            TableSymbols::Normal(me, columns) => {
                if me == table {
                    columns.get(symbol).map(|s| (me.clone(), s.to_owned()))
                } else {
                    None
                }
            }
            TableSymbols::Alias {
                alias_name,
                real_name,
                columns,
            } => {
                if alias_name == table {
                    columns
                        .get(symbol)
                        .map(|s| (real_name.clone(), s.to_owned()))
                } else {
                    None
                }
            }
        }
    }
}

/// An ordered list of tables created from the successively `FROM` clauses of a
/// query, forming the symbol table for the `SELECT` body at the same level.
struct TableStack<C: ContextProvider> {
    /// Each element in this stack represent the tables introduced in a
    /// dependent `FROM` statement.
    tables: Vec<Vec<TableSymbols>>,
    context: C,
}
impl<C: ContextProvider> TableStack<C> {
    /// Create a new empty [`TableStack`]
    fn new(context: C) -> Self {
        TableStack {
            tables: Vec::new(),
            context,
        }
    }

    /// Takes a symbol addressing a column in a zkDB pseuo-table and convert it
    /// into a JSONB access into the actual table
    fn resolve(&self, symbol: &Ident) -> Result<Option<Expr>> {
        let candidates = self
            .tables
            .iter()
            .flat_map(|tables| tables.iter().filter_map(|t| t.resolve(&symbol.value)))
            .collect::<HashSet<_>>(); // The same table may appear at multiple level, so deduplicate
        ensure!(!candidates.is_empty(), "column `{symbol}` does not exist");
        ensure!(candidates.len() <= 1, "column `{symbol}` is ambiguous");

        Ok(candidates
            .into_iter()
            .next()
            .map(|(table, column)| Expr::BinaryOp {
                left: Box::new(Expr::CompoundIdentifier(
                    [Ident::new(table), Ident::new("payload")].to_vec(),
                )),
                op: sqlparser::ast::BinaryOperator::Arrow,
                right: Box::new(Expr::Identifier(Ident::new(column))),
            }))
    }

    fn resolve_compound(&self, compound: &[Ident]) -> Result<Option<Expr>> {
        ensure!(
            compound.len() == 2,
            "`{compound:?}`: deeply coumpounded symbols are not supported"
        );
        let candidates = self
            .tables
            .iter()
            .flat_map(|tables| {
                tables
                    .iter()
                    .filter_map(|t| t.resolve_qualified(&compound[0].value, &compound[1].value))
            })
            .collect::<HashSet<_>>(); // The same table may appear at multiple level, so deduplicate
        ensure!(candidates.len() <= 1, "column `{compound:?}` is ambiguous");

        Ok(candidates
            .into_iter()
            .next()
            .map(|(table, column)| Expr::BinaryOp {
                left: Box::new(Expr::CompoundIdentifier(
                    [Ident::new(table), Ident::new("payload")].to_vec(),
                )),
                op: sqlparser::ast::BinaryOperator::Arrow,
                right: Box::new(Expr::Identifier(Ident::new(column))),
            }))
    }

    fn extends_with<'a, I: Iterator<Item = &'a TableFactor>>(&mut self, tables: I) -> Result<()> {
        self.tables.push(Vec::new());
        for table in tables {
            match table {
                TableFactor::Table {
                    name, alias, args, ..
                } => {
                    if args.is_some() {
                        debug!("ignoring tablue-valued function {name}");
                    } else {
                        ensure!(
                            name.0.len() == 1,
                            "compounded table names unsupported: `{}`",
                            name
                        );
                        let real_name = &name.0[0].value;
                        let columns = self
                            .context
                            .fetch_table(&real_name)?
                            .columns
                            .into_iter()
                            .map(|c| c.name)
                            .collect::<HashSet<_>>();
                        self.tables
                            .last_mut()
                            .unwrap()
                            .push(if let Some(alias) = alias {
                                TableSymbols::Alias {
                                    alias_name: alias.name.value.to_owned(),
                                    real_name: real_name.to_owned(),
                                    columns,
                                }
                            } else {
                                TableSymbols::Normal(real_name.to_owned(), columns)
                            });
                    }
                }
                TableFactor::Derived { .. }
                | TableFactor::TableFunction { .. }
                | TableFactor::Function { .. }
                | TableFactor::UNNEST { .. } => {}
                TableFactor::JsonTable { .. } => unreachable!(),
                TableFactor::NestedJoin {
                    table_with_joins: _,
                    alias: _,
                } => todo!(),
                TableFactor::Pivot { .. }
                | TableFactor::Unpivot { .. }
                | TableFactor::MatchRecognize { .. } => unreachable!(),
            }
        }
        Ok(())
    }
}

fn retarget_expr<C: ContextProvider>(e: &mut Expr, ctx: &mut TableStack<C>) -> Result<()> {
    match e {
        Expr::Identifier(symbol) => {
            if let Some(new_e) = ctx.resolve(symbol)? {
                *e = new_e;
            }
        }
        Expr::CompoundIdentifier(compound) => {
            if let Some(new_e) = ctx.resolve_compound(compound)? {
                *e = new_e;
            }
        }
        Expr::JsonAccess { .. } | Expr::CompositeAccess { .. } => unreachable!(),
        Expr::IsFalse(e)
        | Expr::IsNotFalse(e)
        | Expr::IsTrue(e)
        | Expr::IsNotTrue(e)
        | Expr::IsNull(e)
        | Expr::IsNotNull(e)
        | Expr::IsUnknown(e)
        | Expr::IsNotUnknown(e) => {
            retarget_expr(e, ctx)?;
        }
        Expr::IsDistinctFrom(e1, e2) | Expr::IsNotDistinctFrom(e1, e2) => {
            retarget_expr(e1, ctx)?;
            retarget_expr(e2, ctx)?;
        }
        Expr::InList { expr, list, .. } => {
            retarget_expr(expr, ctx)?;
            for e in list.iter_mut() {
                retarget_expr(e, ctx)?;
            }
        }
        Expr::InSubquery { expr, subquery, .. } => {
            retarget_expr(expr, ctx)?;
            retarget_query(subquery, ctx)?;
        }
        Expr::InUnnest {
            expr, array_expr, ..
        } => {
            retarget_expr(expr, ctx)?;
            retarget_expr(array_expr, ctx)?;
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            retarget_expr(expr, ctx)?;
            retarget_expr(low, ctx)?;
            retarget_expr(high, ctx)?;
        }
        Expr::BinaryOp { left, right, .. } => {
            retarget_expr(left, ctx)?;
            retarget_expr(right, ctx)?;
        }
        Expr::Like { .. } | Expr::ILike { .. } | Expr::SimilarTo { .. } | Expr::RLike { .. } => {
            unreachable!()
        }
        Expr::AnyOp { left, right, .. } | Expr::AllOp { left, right, .. } => {
            retarget_expr(left, ctx)?;
            retarget_expr(right, ctx)?;
        }
        Expr::UnaryOp { expr, .. } => retarget_expr(expr, ctx)?,
        Expr::Convert { .. }
        | Expr::Cast { .. }
        | Expr::AtTimeZone { .. }
        | Expr::Extract { .. }
        | Expr::Ceil { .. }
        | Expr::Floor { .. }
        | Expr::Position { .. }
        | Expr::Substring { .. }
        | Expr::Trim { .. }
        | Expr::Overlay { .. }
        | Expr::Collate { .. } => unreachable!(),
        Expr::Nested(e) => {
            retarget_expr(e, ctx)?;
        }
        Expr::Value(_) => {}
        Expr::IntroducedString { .. } | Expr::TypedString { .. } | Expr::MapAccess { .. } => {
            unreachable!()
        }
        Expr::Function(_) => todo!(),
        Expr::Case {
            operand,
            conditions,
            results,
            else_result,
        } => {
            if let Some(operand) = operand.as_mut() {
                retarget_expr(operand, ctx)?;
            }
            for e in conditions.iter_mut().chain(results.iter_mut()) {
                retarget_expr(e, ctx)?;
            }
            if let Some(else_expr) = else_result.as_mut() {
                retarget_expr(else_expr, ctx)?;
            }
        }
        Expr::Exists { subquery, .. } | Expr::Subquery(subquery) => retarget_query(subquery, ctx)?,
        Expr::GroupingSets(ess) | Expr::Cube(ess) | Expr::Rollup(ess) => {
            for es in ess.iter_mut() {
                for e in es.iter_mut() {
                    retarget_expr(e, ctx)?;
                }
            }
        }
        Expr::Tuple(es) => {
            for e in es.iter_mut() {
                retarget_expr(e, ctx)?;
            }
        }
        Expr::Struct { .. } | Expr::Named { .. } | Expr::Dictionary(_) => unreachable!(),
        Expr::Array(_) | Expr::Interval(_) => {}
        Expr::MatchAgainst { .. } => unreachable!(),
        Expr::Wildcard | Expr::QualifiedWildcard(_) => {}
        Expr::OuterJoin(_) => unreachable!(),
        Expr::Prior(e) => retarget_expr(e, ctx)?,
        Expr::Subscript { expr, subscript } => {
            retarget_expr(expr, ctx)?;
            match subscript.as_mut() {
                Subscript::Index { index } => {
                    retarget_expr(index, ctx)?;
                }
                Subscript::Slice {
                    lower_bound,
                    upper_bound,
                    stride,
                } => {
                    if let Some(lower_bound) = lower_bound.as_mut() {
                        retarget_expr(lower_bound, ctx)?;
                    }
                    if let Some(upper_bound) = upper_bound.as_mut() {
                        retarget_expr(upper_bound, ctx)?;
                    }
                    if let Some(stride) = stride.as_mut() {
                        retarget_expr(stride, ctx)?;
                    }
                }
            }
        }
        Expr::Map(_) | Expr::Lambda(_) => unreachable!(),
    }
    Ok(())
}

fn retarget_select<C: ContextProvider>(select: &mut Select, ctx: &mut TableStack<C>) -> Result<()> {
    ctx.extends_with(
        select
            .from
            .iter()
            .flat_map(|t| std::iter::once(&t.relation).chain(t.joins.iter().map(|j| &j.relation))),
    )?;
    for s in select.projection.iter_mut() {
        retarget_select_item(s, ctx)?;
    }

    if let Some(selection) = select.selection.as_mut() {
        retarget_expr(selection, ctx)?;
    }

    match select.group_by {
        GroupByExpr::All(_) => unreachable!(),
        GroupByExpr::Expressions(ref mut es, _) => {
            for e in es.iter_mut() {
                retarget_expr(e, ctx)?;
            }
        }
    }

    if let Some(having) = select.having.as_mut() {
        retarget_expr(having, ctx)?;
    }

    Ok(())
}

fn retarget_select_item<C: ContextProvider>(
    item: &mut SelectItem,
    ctx: &mut TableStack<C>,
) -> Result<()> {
    match item {
        SelectItem::UnnamedExpr(e) => retarget_expr(e, ctx)?,
        SelectItem::ExprWithAlias { expr, .. } => retarget_expr(expr, ctx)?,
        SelectItem::QualifiedWildcard(_, _) | SelectItem::Wildcard(_) => unreachable!(),
    }
    Ok(())
}

fn retarget_setexpr<C: ContextProvider>(s: &mut SetExpr, ctx: &mut TableStack<C>) -> Result<()> {
    match s {
        SetExpr::Select(ref mut select) => retarget_select(select, ctx),
        SetExpr::Query(ref mut query) => retarget_query(query, ctx),
        SetExpr::SetOperation {
            op: _,
            set_quantifier: _,
            ref mut left,
            ref mut right,
        } => retarget_setexpr(left, ctx).and_then(|_| retarget_setexpr(right, ctx)),
        SetExpr::Values(_) | SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Table(_) => Ok(()),
    }
}

fn retarget_query<C: ContextProvider>(q: &mut Query, ctx: &mut TableStack<C>) -> Result<()> {
    retarget_setexpr(&mut q.body, ctx)?;
    for order_by in q.order_by.iter_mut() {
        for e in order_by.exprs.iter_mut() {
            retarget_expr(&mut e.expr, ctx)?;
        }
    }
    Ok(())
}

pub fn execute<C: ContextProvider>(q: &Query, context: C) -> Result<()> {
    let mut converted_query = q.clone();
    let mut context = TableStack::new(context);
    retarget_query(&mut converted_query, &mut context)?;
    println!("Original query:\n>> {}", q);
    println!("Translated query:\n>> {}", converted_query);
    Ok(())
}
