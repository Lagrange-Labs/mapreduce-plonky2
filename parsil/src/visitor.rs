//! This implements a generic visitor patter for an SQL AST. One is already
//! defined in sqlparser, but its public interface is unfortunately restricte to
//! only some node types, hence making it unfit for our needs.
use sqlparser::ast::{
    BinaryOperator, Distinct, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArgumentList,
    FunctionArguments, GroupByExpr, Join, JoinConstraint, JoinOperator, NamedWindowDefinition,
    NamedWindowExpr, Offset, OrderBy, OrderByExpr, Query, Select, SelectItem, SetExpr, Statement,
    TableFactor, TableWithJoins, UnaryOperator, Values, WindowSpec, WindowType,
};

/// From an AST node type, generate two default empty visitor methods for pre_
/// and post_ visit hooks.
///
/// Example:
///
/// ```ignore
/// visit_for!(Query Statement)
/// ```
///
/// will expand to:
///
/// ```ignore
/// fn pre_query(&mut self, query: &mut Query) -> Result<()> {
///     Ok(())
/// }
/// fn post_query(&mut self, query: &mut Query) -> Result<()> {
///     Ok(())
/// }
/// fn pre_statement(&mut self, statement: &mut Statement) -> Result<()> {
///     Ok(())
/// }
/// fn post_statement(&mut self, statement: &mut Statement) -> Result<()> {
///     Ok(())
/// }
/// ```
macro_rules! visit {
    ( $( $type: ident )* ) => {
        $(
            camelpaste::item! {
                #[allow(unused)]
                fn [<pre_ $type:snake>](&mut self, [<$type:snake>]: &$type) -> Result<(), Self::Error> {
                    Ok(())
                }

                #[allow(unused)]
                fn [<post_ $type:snake>](&mut self, [<$type:snake>]: &$type) -> Result<(), Self::Error> {
                    Ok(())
                }
            }
        )*
    };
}

macro_rules! visit_mut {
    ( $( $type: ident )* ) => {
        $(
            camelpaste::item! {
                #[allow(unused)]
                fn [<pre_ $type:snake>](&mut self, [<$type:snake>]: &mut $type) -> Result<(), Self::Error> {
                    Ok(())
                }

                #[allow(unused)]
                fn [<post_ $type:snake>](&mut self, [<$type:snake>]: &mut $type) -> Result<(), Self::Error> {
                    Ok(())
                }
            }
        )*
    };
}

pub trait AstVisitor {
    type Error;

    visit!(
            BinaryOperator
            Distinct
            Expr
            FunctionArg
            FunctionArguments
            Join
            JoinConstraint
            JoinOperator
            Offset
            OrderBy
            OrderByExpr
            Query
            Select
            SelectItem
            SetExpr
            Statement
            TableFactor
            TableWithJoins
            UnaryOperator
            Values
            WindowSpec
    );

    /// Called before traversing a WHERE
    fn pre_selection(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called after traversing a WHERE
    fn post_selection(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}
pub trait Visit<P: AstVisitor> {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error>;
}
impl<P: AstVisitor> Visit<P> for WindowSpec {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_window_spec(self)?;
        for e in self.partition_by.iter() {
            e.visit(pass)?
        }
        pass.post_window_spec(self)
    }
}
impl<P: AstVisitor> Visit<P> for Offset {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_offset(self)?;
        self.value.visit(pass)?;
        pass.post_offset(self)
    }
}
impl<P: AstVisitor> Visit<P> for FunctionArguments {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_function_arguments(self)?;
        match self {
            FunctionArguments::None => {}
            FunctionArguments::Subquery(q) => q.visit(pass)?,
            FunctionArguments::List(FunctionArgumentList { args, .. }) => {
                for arg in args {
                    arg.visit(pass)?;
                }
            }
        };
        pass.post_function_arguments(self)
    }
}
impl<P: AstVisitor> Visit<P> for UnaryOperator {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_unary_operator(self)?;
        pass.post_unary_operator(self)
    }
}
impl<P: AstVisitor> Visit<P> for BinaryOperator {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_binary_operator(self)?;
        pass.post_binary_operator(self)
    }
}
impl<P: AstVisitor> Visit<P> for Expr {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_expr(self)?;
        match self {
            Expr::Identifier(_) => {}
            Expr::CompoundIdentifier(_) => {}
            Expr::JsonAccess { value, .. } => value.visit(pass)?,
            Expr::CompositeAccess { expr, .. } => expr.visit(pass)?,
            Expr::IsFalse(expr)
            | Expr::IsNotFalse(expr)
            | Expr::IsTrue(expr)
            | Expr::IsNotTrue(expr)
            | Expr::IsNull(expr)
            | Expr::IsNotNull(expr)
            | Expr::IsUnknown(expr)
            | Expr::IsNotUnknown(expr) => expr.visit(pass)?,
            Expr::IsDistinctFrom(left, right) | Expr::IsNotDistinctFrom(left, right) => {
                left.visit(pass)?;
                right.visit(pass)?;
            }
            Expr::InList { expr, list, .. } => {
                expr.visit(pass)?;
                for e in list.iter() {
                    e.visit(pass)?;
                }
            }
            Expr::InSubquery { expr, subquery, .. } => {
                expr.visit(pass)?;
                subquery.visit(pass)?;
            }
            Expr::InUnnest {
                expr, array_expr, ..
            } => {
                expr.visit(pass)?;
                array_expr.visit(pass)?;
            }
            Expr::Between {
                expr, low, high, ..
            } => {
                expr.visit(pass)?;
                low.visit(pass)?;
                high.visit(pass)?;
            }
            Expr::BinaryOp { left, op, right } => {
                left.visit(pass)?;
                op.visit(pass)?;
                right.visit(pass)?;
            }
            Expr::Like { expr, pattern, .. }
            | Expr::ILike { expr, pattern, .. }
            | Expr::SimilarTo { expr, pattern, .. }
            | Expr::RLike { expr, pattern, .. } => {
                expr.visit(pass)?;
                pattern.visit(pass)?;
            }
            Expr::AnyOp { left, right, .. } | Expr::AllOp { left, right, .. } => {
                left.visit(pass)?;
                right.visit(pass)?;
            }
            Expr::UnaryOp { expr, op } => {
                op.visit(pass)?;
                expr.visit(pass)?;
            }
            Expr::Overlay {
                expr,
                overlay_what,
                overlay_from,
                overlay_for,
            } => {
                expr.visit(pass)?;
                overlay_what.visit(pass)?;
                overlay_from.visit(pass)?;
                if let Some(overlay_for) = overlay_for.as_ref() {
                    overlay_for.visit(pass)?;
                }
            }
            Expr::Collate { expr, .. } => expr.visit(pass)?,
            Expr::Nested(e) => e.visit(pass)?,
            Expr::Function(Function {
                parameters,
                args,
                filter,
                over,
                within_group,
                ..
            }) => {
                parameters.visit(pass)?;
                args.visit(pass)?;
                if let Some(filter) = filter.as_ref() {
                    filter.visit(pass)?;
                }
                if let Some(over) = over.as_ref() {
                    match over {
                        WindowType::WindowSpec(window_spec) => {
                            window_spec.visit(pass)?;
                        }
                        WindowType::NamedWindow(_) => {}
                    }
                }
                for e in within_group.iter() {
                    e.visit(pass)?;
                }
            }
            Expr::Case {
                operand,
                conditions,
                results,
                else_result,
            } => {
                if let Some(operand) = operand.as_ref() {
                    operand.visit(pass)?;
                }
                for e in conditions.iter().chain(results.iter()) {
                    e.visit(pass)?;
                }
                if let Some(else_result) = else_result.as_ref() {
                    else_result.visit(pass)?;
                }
            }
            Expr::Exists { subquery, .. } => subquery.visit(pass)?,
            Expr::Subquery(q) => q.visit(pass)?,
            Expr::GroupingSets(_) => todo!(),
            Expr::Cube(exprss) | Expr::Rollup(exprss) => {
                for e in exprss.iter().flat_map(|exprs| exprs.iter()) {
                    e.visit(pass)?;
                }
            }
            Expr::Tuple(exprs) => {
                for e in exprs.iter() {
                    e.visit(pass)?
                }
            }
            Expr::Subscript { expr, .. } => expr.visit(pass)?,
            Expr::Array(array) => {
                for e in array.elem.iter() {
                    e.visit(pass)?;
                }
            }
            _ => {}
        }
        pass.post_expr(self)
    }
}
impl<P: AstVisitor> Visit<P> for OrderByExpr {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_order_by_expr(self)?;
        self.expr.visit(pass)?;
        pass.post_order_by_expr(self)
    }
}
impl<P: AstVisitor> Visit<P> for OrderBy {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_order_by(self)?;
        for e in self.exprs.iter() {
            e.visit(pass)?;
        }
        pass.post_order_by(self)
    }
}
impl<P: AstVisitor> Visit<P> for FunctionArg {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_function_arg(self)?;
        match self {
            FunctionArg::Named { arg, .. } | FunctionArg::Unnamed(arg) => match arg {
                FunctionArgExpr::Expr(e) => e.visit(pass)?,
                FunctionArgExpr::QualifiedWildcard(_) => {}
                FunctionArgExpr::Wildcard => {}
            },
        }
        pass.post_function_arg(self)
    }
}
impl<P: AstVisitor> Visit<P> for TableFactor {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_table_factor(self)?;
        match self {
            TableFactor::Table {
                args,
                // Do not visit, MSSQL specific
                with_hints: _,
                // Do not visit, BigQuery/MSSQL specific
                version: _,
                // Do no visit, MySQL-specific
                partitions: _,
                ..
            } => {
                if let Some(args) = args {
                    for arg in args.iter() {
                        arg.visit(pass)?;
                    }
                }
            }
            TableFactor::Derived { subquery, .. } => subquery.visit(pass)?,
            TableFactor::TableFunction { expr, .. } => expr.visit(pass)?,
            TableFactor::Function { args, .. } => {
                for arg in args.iter() {
                    arg.visit(pass)?;
                }
            }
            TableFactor::UNNEST { array_exprs, .. } => {
                for e in array_exprs.iter() {
                    e.visit(pass)?;
                }
            }
            TableFactor::JsonTable { .. } => unreachable!("non-standard"),
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => {
                table_with_joins.visit(pass)?;
            }
            TableFactor::Pivot { .. }
            | TableFactor::Unpivot { .. }
            | TableFactor::MatchRecognize { .. } => unreachable!("Snowflake"),
        }
        pass.post_table_factor(self)
    }
}
impl<P: AstVisitor> Visit<P> for Join {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_join(self)?;
        self.relation.visit(pass)?;
        self.join_operator.visit(pass)?;
        pass.post_join(self)
    }
}
impl<P: AstVisitor> Visit<P> for SelectItem {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_select_item(self)?;
        match self {
            SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                expr.visit(pass)?
            }
            SelectItem::QualifiedWildcard(_, _) | SelectItem::Wildcard(_) => {}
        }
        pass.post_select_item(self)
    }
}
impl<P: AstVisitor> Visit<P> for JoinOperator {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_join_operator(self)?;
        match self {
            JoinOperator::Inner(constraint)
            | JoinOperator::LeftOuter(constraint)
            | JoinOperator::RightOuter(constraint)
            | JoinOperator::FullOuter(constraint)
            | JoinOperator::LeftSemi(constraint)
            | JoinOperator::RightSemi(constraint)
            | JoinOperator::LeftAnti(constraint)
            | JoinOperator::RightAnti(constraint)
            | JoinOperator::AsOf { constraint, .. } => constraint.visit(pass)?,
            JoinOperator::CrossJoin | JoinOperator::CrossApply | JoinOperator::OuterApply => {}
        }
        pass.post_join_operator(self)
    }
}
impl<P: AstVisitor> Visit<P> for JoinConstraint {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_join_constraint(self)?;
        match self {
            JoinConstraint::On(e) => e.visit(pass)?,
            JoinConstraint::Using(_) | JoinConstraint::Natural | JoinConstraint::None => {}
        }
        pass.post_join_constraint(self)
    }
}
impl<P: AstVisitor> Visit<P> for TableWithJoins {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_table_with_joins(self)?;
        self.relation.visit(pass)?;
        for j in self.joins.iter() {
            j.visit(pass)?;
        }
        pass.post_table_with_joins(self)
    }
}
impl<P: AstVisitor> Visit<P> for Distinct {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_distinct(self)?;
        match self {
            Distinct::Distinct => {}
            Distinct::On(exprs) => {
                for e in exprs.iter() {
                    e.visit(pass)?;
                }
            }
        }
        pass.post_distinct(self)
    }
}
impl<P: AstVisitor> Visit<P> for Select {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_select(self)?;

        for f in self.from.iter() {
            f.visit(pass)?;
        }

        if let Some(distinct) = self.distinct.as_ref() {
            distinct.visit(pass)?;
        }

        if let Some(selection) = self.selection.as_ref() {
            pass.pre_selection()?;
            selection.visit(pass)?;
            pass.post_selection()?;
        }

        match &self.group_by {
            GroupByExpr::All(_) => unreachable!(),
            GroupByExpr::Expressions(exprs, _) => {
                for e in exprs.iter() {
                    e.visit(pass)?;
                }
            }
        }

        if let Some(having) = self.having.as_ref() {
            having.visit(pass)?;
        }

        for NamedWindowDefinition(_, window_expr) in self.named_window.iter() {
            match window_expr {
                NamedWindowExpr::NamedWindow(_) => todo!(),
                NamedWindowExpr::WindowSpec(spec) => spec.visit(pass)?,
            }
        }

        // The projection is visited last, as its components may only be
        // resolved after the other elements have been visited.
        for p in self.projection.iter() {
            p.visit(pass)?;
        }

        pass.post_select(self)
    }
}
impl<P: AstVisitor> Visit<P> for Statement {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_statement(self)?;
        match self {
            Statement::Query(q) => q.visit(pass)?,
            Statement::Analyze { .. }
            | Statement::Truncate { .. }
            | Statement::Msck { .. }
            | Statement::Insert(_)
            | Statement::Install { .. }
            | Statement::Call(_)
            | Statement::Copy { .. }
            | Statement::CopyIntoSnowflake { .. }
            | Statement::Close { .. }
            | Statement::Update { .. }
            | Statement::Delete(_)
            | Statement::CreateView { .. }
            | Statement::CreateTable(_)
            | Statement::CreateVirtualTable { .. }
            | Statement::CreateIndex(_)
            | Statement::CreateRole { .. }
            | Statement::CreateSecret { .. }
            | Statement::AlterTable { .. }
            | Statement::AlterIndex { .. }
            | Statement::AlterView { .. }
            | Statement::AlterRole { .. }
            | Statement::AttachDatabase { .. }
            | Statement::AttachDuckDBDatabase { .. }
            | Statement::DetachDuckDBDatabase { .. }
            | Statement::Drop { .. }
            | Statement::DropFunction { .. }
            | Statement::DropProcedure { .. }
            | Statement::DropSecret { .. }
            | Statement::Declare { .. }
            | Statement::CreateExtension { .. }
            | Statement::Fetch { .. }
            | Statement::Flush { .. }
            | Statement::Discard { .. }
            | Statement::SetRole { .. }
            | Statement::SetVariable { .. }
            | Statement::SetTimeZone { .. }
            | Statement::SetNames { .. }
            | Statement::SetNamesDefault {}
            | Statement::ShowFunctions { .. }
            | Statement::ShowVariable { .. }
            | Statement::ShowStatus { .. }
            | Statement::ShowVariables { .. }
            | Statement::ShowCreate { .. }
            | Statement::ShowColumns { .. }
            | Statement::ShowTables { .. }
            | Statement::ShowCollation { .. }
            | Statement::Use { .. }
            | Statement::StartTransaction { .. }
            | Statement::SetTransaction { .. }
            | Statement::Comment { .. }
            | Statement::Commit { .. }
            | Statement::Rollback { .. }
            | Statement::CreateSchema { .. }
            | Statement::CreateDatabase { .. }
            | Statement::CreateFunction { .. }
            | Statement::CreateProcedure { .. }
            | Statement::CreateMacro { .. }
            | Statement::CreateStage { .. }
            | Statement::Assert { .. }
            | Statement::Grant { .. }
            | Statement::Revoke { .. }
            | Statement::Deallocate { .. }
            | Statement::Execute { .. }
            | Statement::Prepare { .. }
            | Statement::Kill { .. }
            | Statement::ExplainTable { .. }
            | Statement::Explain { .. }
            | Statement::Savepoint { .. }
            | Statement::ReleaseSavepoint { .. }
            | Statement::Merge { .. }
            | Statement::Cache { .. }
            | Statement::UNCache { .. }
            | Statement::CreateSequence { .. }
            | Statement::CreateType { .. }
            | Statement::Pragma { .. }
            | Statement::LockTables { .. }
            | Statement::UnlockTables
            | Statement::Unload { .. }
            | Statement::Load { .. }
            | Statement::Directory { .. } => {}
        }
        pass.post_statement(self)?;
        Ok(())
    }
}
impl<P: AstVisitor> Visit<P> for SetExpr {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_set_expr(self)?;
        match self {
            SetExpr::Select(s) => s.visit(pass)?,
            SetExpr::Query(q) => q.visit(pass)?,
            SetExpr::SetOperation { left, right, .. } => {
                left.visit(pass)?;
                right.visit(pass)?;
            }
            SetExpr::Values(values) => {
                for v in values.rows.iter().flat_map(|r| r.iter()) {
                    v.visit(pass)?;
                }
            }
            SetExpr::Insert(statement) | SetExpr::Update(statement) => statement.visit(pass)?,
            SetExpr::Table(_) => todo!(),
        }
        pass.post_set_expr(self)
    }
}

impl<P: AstVisitor> Visit<P> for Query {
    fn visit(&self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_query(self)?;
        self.body.visit(pass)?;
        if let Some(order_by) = self.order_by.as_ref() {
            order_by.visit(pass)?;
        }
        if let Some(limit) = self.limit.as_ref() {
            limit.visit(pass)?;
        }
        pass.post_query(self)
    }
}

pub trait AstMutator {
    type Error;

    visit_mut!(
            BinaryOperator
            Distinct
            Expr
            FunctionArg
            FunctionArguments
            Join
            JoinConstraint
            JoinOperator
            Offset
            OrderBy
            OrderByExpr
            Query
            Select
            SelectItem
            SetExpr
            Statement
            TableFactor
            TableWithJoins
            UnaryOperator
            Values
            WindowSpec
    );

    /// Called before traversing a WHERE
    fn pre_selection(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Called after traversing a WHERE
    fn post_selection(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub trait VisitMut<P: AstMutator> {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error>;
}
impl<P: AstMutator> VisitMut<P> for WindowSpec {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_window_spec(self)?;
        for e in self.partition_by.iter_mut() {
            e.visit_mut(pass)?
        }
        pass.post_window_spec(self)
    }
}
impl<P: AstMutator> VisitMut<P> for Offset {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_offset(self)?;
        self.value.visit_mut(pass)?;
        pass.post_offset(self)
    }
}
impl<P: AstMutator> VisitMut<P> for FunctionArguments {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_function_arguments(self)?;
        match self {
            FunctionArguments::None => {}
            FunctionArguments::Subquery(q) => q.visit_mut(pass)?,
            FunctionArguments::List(FunctionArgumentList { args, .. }) => {
                for arg in args {
                    arg.visit_mut(pass)?;
                }
            }
        };
        pass.post_function_arguments(self)
    }
}
impl<P: AstMutator> VisitMut<P> for UnaryOperator {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_unary_operator(self)?;
        pass.post_unary_operator(self)
    }
}
impl<P: AstMutator> VisitMut<P> for BinaryOperator {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_binary_operator(self)?;
        pass.post_binary_operator(self)
    }
}
impl<P: AstMutator> VisitMut<P> for Expr {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_expr(self)?;
        match self {
            Expr::Identifier(_) => {}
            Expr::CompoundIdentifier(_) => {}
            Expr::JsonAccess { value, .. } => value.visit_mut(pass)?,
            Expr::CompositeAccess { expr, .. } => expr.visit_mut(pass)?,
            Expr::IsFalse(expr)
            | Expr::IsNotFalse(expr)
            | Expr::IsTrue(expr)
            | Expr::IsNotTrue(expr)
            | Expr::IsNull(expr)
            | Expr::IsNotNull(expr)
            | Expr::IsUnknown(expr)
            | Expr::IsNotUnknown(expr) => expr.visit_mut(pass)?,
            Expr::IsDistinctFrom(left, right) | Expr::IsNotDistinctFrom(left, right) => {
                left.visit_mut(pass)?;
                right.visit_mut(pass)?;
            }
            Expr::InList { expr, list, .. } => {
                expr.visit_mut(pass)?;
                for e in list.iter_mut() {
                    e.visit_mut(pass)?;
                }
            }
            Expr::InSubquery { expr, subquery, .. } => {
                expr.visit_mut(pass)?;
                subquery.visit_mut(pass)?;
            }
            Expr::InUnnest {
                expr, array_expr, ..
            } => {
                expr.visit_mut(pass)?;
                array_expr.visit_mut(pass)?;
            }
            Expr::Between {
                expr, low, high, ..
            } => {
                expr.visit_mut(pass)?;
                low.visit_mut(pass)?;
                high.visit_mut(pass)?;
            }
            Expr::BinaryOp { left, op, right } => {
                left.visit_mut(pass)?;
                op.visit_mut(pass)?;
                right.visit_mut(pass)?;
            }
            Expr::Like { expr, pattern, .. }
            | Expr::ILike { expr, pattern, .. }
            | Expr::SimilarTo { expr, pattern, .. }
            | Expr::RLike { expr, pattern, .. } => {
                expr.visit_mut(pass)?;
                pattern.visit_mut(pass)?;
            }
            Expr::AnyOp { left, right, .. } | Expr::AllOp { left, right, .. } => {
                left.visit_mut(pass)?;
                right.visit_mut(pass)?;
            }
            Expr::UnaryOp { expr, op } => {
                op.visit_mut(pass)?;
                expr.visit_mut(pass)?;
            }
            Expr::Overlay {
                expr,
                overlay_what,
                overlay_from,
                overlay_for,
            } => {
                expr.visit_mut(pass)?;
                overlay_what.visit_mut(pass)?;
                overlay_from.visit_mut(pass)?;
                if let Some(overlay_for) = overlay_for.as_mut() {
                    overlay_for.visit_mut(pass)?;
                }
            }
            Expr::Collate { expr, .. } => expr.visit_mut(pass)?,
            Expr::Nested(e) => e.visit_mut(pass)?,
            Expr::Function(Function {
                parameters,
                args,
                filter,
                over,
                within_group,
                ..
            }) => {
                parameters.visit_mut(pass)?;
                args.visit_mut(pass)?;
                if let Some(filter) = filter.as_mut() {
                    filter.visit_mut(pass)?;
                }
                if let Some(over) = over.as_mut() {
                    match over {
                        WindowType::WindowSpec(window_spec) => {
                            window_spec.visit_mut(pass)?;
                        }
                        WindowType::NamedWindow(_) => {}
                    }
                }
                for e in within_group.iter_mut() {
                    e.visit_mut(pass)?;
                }
            }
            Expr::Case {
                operand,
                conditions,
                results,
                else_result,
            } => {
                if let Some(operand) = operand.as_mut() {
                    operand.visit_mut(pass)?;
                }
                for e in conditions.iter_mut().chain(results.iter_mut()) {
                    e.visit_mut(pass)?;
                }
                if let Some(else_result) = else_result.as_mut() {
                    else_result.visit_mut(pass)?;
                }
            }
            Expr::Exists { subquery, .. } => subquery.visit_mut(pass)?,
            Expr::Subquery(q) => q.visit_mut(pass)?,
            Expr::GroupingSets(_) => todo!(),
            Expr::Cube(exprss) | Expr::Rollup(exprss) => {
                for e in exprss.iter_mut().flat_map(|exprs| exprs.iter_mut()) {
                    e.visit_mut(pass)?;
                }
            }
            Expr::Tuple(exprs) => {
                for e in exprs.iter_mut() {
                    e.visit_mut(pass)?
                }
            }
            Expr::Subscript { expr, .. } => expr.visit_mut(pass)?,
            Expr::Array(array) => {
                for e in array.elem.iter_mut() {
                    e.visit_mut(pass)?;
                }
            }
            _ => {}
        }
        pass.post_expr(self)
    }
}
impl<P: AstMutator> VisitMut<P> for OrderByExpr {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_order_by_expr(self)?;
        self.expr.visit_mut(pass)?;
        pass.post_order_by_expr(self)
    }
}
impl<P: AstMutator> VisitMut<P> for OrderBy {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_order_by(self)?;
        for e in self.exprs.iter_mut() {
            e.visit_mut(pass)?;
        }
        pass.post_order_by(self)
    }
}
impl<P: AstMutator> VisitMut<P> for FunctionArg {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_function_arg(self)?;
        match self {
            FunctionArg::Named { arg, .. } | FunctionArg::Unnamed(arg) => match arg {
                FunctionArgExpr::Expr(e) => e.visit_mut(pass)?,
                FunctionArgExpr::QualifiedWildcard(_) => {}
                FunctionArgExpr::Wildcard => {}
            },
        }
        pass.post_function_arg(self)
    }
}
impl<P: AstMutator> VisitMut<P> for TableFactor {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_table_factor(self)?;
        match self {
            TableFactor::Table {
                args,
                // Do not visit, MSSQL specific
                with_hints: _,
                // Do not visit, BigQuery/MSSQL specific
                version: _,
                // Do no visit, MySQL-specific
                partitions: _,
                ..
            } => {
                if let Some(args) = args {
                    for arg in args.iter_mut() {
                        arg.visit_mut(pass)?;
                    }
                }
            }
            TableFactor::Derived { subquery, .. } => subquery.visit_mut(pass)?,
            TableFactor::TableFunction { expr, .. } => expr.visit_mut(pass)?,
            TableFactor::Function { args, .. } => {
                for arg in args.iter_mut() {
                    arg.visit_mut(pass)?;
                }
            }
            TableFactor::UNNEST { array_exprs, .. } => {
                for e in array_exprs.iter_mut() {
                    e.visit_mut(pass)?;
                }
            }
            TableFactor::JsonTable { .. } => unreachable!("non-standard"),
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => {
                table_with_joins.visit_mut(pass)?;
            }
            TableFactor::Pivot { .. }
            | TableFactor::Unpivot { .. }
            | TableFactor::MatchRecognize { .. } => unreachable!("Snowflake"),
        }
        pass.post_table_factor(self)
    }
}
impl<P: AstMutator> VisitMut<P> for Join {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_join(self)?;
        self.relation.visit_mut(pass)?;
        self.join_operator.visit_mut(pass)?;
        pass.post_join(self)
    }
}
impl<P: AstMutator> VisitMut<P> for SelectItem {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_select_item(self)?;
        match self {
            SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                expr.visit_mut(pass)?
            }
            SelectItem::QualifiedWildcard(_, _) | SelectItem::Wildcard(_) => {}
        }
        pass.post_select_item(self)
    }
}
impl<P: AstMutator> VisitMut<P> for JoinOperator {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_join_operator(self)?;
        match self {
            JoinOperator::Inner(constraint)
            | JoinOperator::LeftOuter(constraint)
            | JoinOperator::RightOuter(constraint)
            | JoinOperator::FullOuter(constraint)
            | JoinOperator::LeftSemi(constraint)
            | JoinOperator::RightSemi(constraint)
            | JoinOperator::LeftAnti(constraint)
            | JoinOperator::RightAnti(constraint)
            | JoinOperator::AsOf { constraint, .. } => constraint.visit_mut(pass)?,
            JoinOperator::CrossJoin | JoinOperator::CrossApply | JoinOperator::OuterApply => {}
        }
        pass.post_join_operator(self)
    }
}
impl<P: AstMutator> VisitMut<P> for JoinConstraint {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_join_constraint(self)?;
        match self {
            JoinConstraint::On(e) => e.visit_mut(pass)?,
            JoinConstraint::Using(_) | JoinConstraint::Natural | JoinConstraint::None => {}
        }
        pass.post_join_constraint(self)
    }
}
impl<P: AstMutator> VisitMut<P> for TableWithJoins {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_table_with_joins(self)?;
        self.relation.visit_mut(pass)?;
        for j in self.joins.iter_mut() {
            j.visit_mut(pass)?;
        }
        pass.post_table_with_joins(self)
    }
}
impl<P: AstMutator> VisitMut<P> for Distinct {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_distinct(self)?;
        match self {
            Distinct::Distinct => {}
            Distinct::On(exprs) => {
                for e in exprs.iter_mut() {
                    e.visit_mut(pass)?;
                }
            }
        }
        pass.post_distinct(self)
    }
}
impl<P: AstMutator> VisitMut<P> for Select {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_select(self)?;

        for f in self.from.iter_mut() {
            f.visit_mut(pass)?;
        }

        if let Some(distinct) = self.distinct.as_mut() {
            distinct.visit_mut(pass)?;
        }

        if let Some(selection) = self.selection.as_mut() {
            pass.pre_selection()?;
            selection.visit_mut(pass)?;
            pass.post_selection()?;
        }

        match &mut self.group_by {
            GroupByExpr::All(_) => unreachable!(),
            GroupByExpr::Expressions(exprs, _) => {
                for e in exprs.iter_mut() {
                    e.visit_mut(pass)?;
                }
            }
        }

        if let Some(having) = self.having.as_mut() {
            having.visit_mut(pass)?;
        }

        for NamedWindowDefinition(_, window_expr) in self.named_window.iter_mut() {
            match window_expr {
                NamedWindowExpr::NamedWindow(_) => todo!(),
                NamedWindowExpr::WindowSpec(spec) => spec.visit_mut(pass)?,
            }
        }

        // The projection is visited last, as its components may only be
        // resolved after the other elements have been visited.
        for p in self.projection.iter_mut() {
            p.visit_mut(pass)?;
        }

        pass.post_select(self)
    }
}
impl<P: AstMutator> VisitMut<P> for Statement {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_statement(self)?;
        match self {
            Statement::Query(q) => q.visit_mut(pass)?,
            Statement::Analyze { .. }
            | Statement::Truncate { .. }
            | Statement::Msck { .. }
            | Statement::Insert(_)
            | Statement::Install { .. }
            | Statement::Call(_)
            | Statement::Copy { .. }
            | Statement::CopyIntoSnowflake { .. }
            | Statement::Close { .. }
            | Statement::Update { .. }
            | Statement::Delete(_)
            | Statement::CreateView { .. }
            | Statement::CreateTable(_)
            | Statement::CreateVirtualTable { .. }
            | Statement::CreateIndex(_)
            | Statement::CreateRole { .. }
            | Statement::CreateSecret { .. }
            | Statement::AlterTable { .. }
            | Statement::AlterIndex { .. }
            | Statement::AlterView { .. }
            | Statement::AlterRole { .. }
            | Statement::AttachDatabase { .. }
            | Statement::AttachDuckDBDatabase { .. }
            | Statement::DetachDuckDBDatabase { .. }
            | Statement::Drop { .. }
            | Statement::DropFunction { .. }
            | Statement::DropProcedure { .. }
            | Statement::DropSecret { .. }
            | Statement::Declare { .. }
            | Statement::CreateExtension { .. }
            | Statement::Fetch { .. }
            | Statement::Flush { .. }
            | Statement::Discard { .. }
            | Statement::SetRole { .. }
            | Statement::SetVariable { .. }
            | Statement::SetTimeZone { .. }
            | Statement::SetNames { .. }
            | Statement::SetNamesDefault {}
            | Statement::ShowFunctions { .. }
            | Statement::ShowVariable { .. }
            | Statement::ShowStatus { .. }
            | Statement::ShowVariables { .. }
            | Statement::ShowCreate { .. }
            | Statement::ShowColumns { .. }
            | Statement::ShowTables { .. }
            | Statement::ShowCollation { .. }
            | Statement::Use { .. }
            | Statement::StartTransaction { .. }
            | Statement::SetTransaction { .. }
            | Statement::Comment { .. }
            | Statement::Commit { .. }
            | Statement::Rollback { .. }
            | Statement::CreateSchema { .. }
            | Statement::CreateDatabase { .. }
            | Statement::CreateFunction { .. }
            | Statement::CreateProcedure { .. }
            | Statement::CreateMacro { .. }
            | Statement::CreateStage { .. }
            | Statement::Assert { .. }
            | Statement::Grant { .. }
            | Statement::Revoke { .. }
            | Statement::Deallocate { .. }
            | Statement::Execute { .. }
            | Statement::Prepare { .. }
            | Statement::Kill { .. }
            | Statement::ExplainTable { .. }
            | Statement::Explain { .. }
            | Statement::Savepoint { .. }
            | Statement::ReleaseSavepoint { .. }
            | Statement::Merge { .. }
            | Statement::Cache { .. }
            | Statement::UNCache { .. }
            | Statement::CreateSequence { .. }
            | Statement::CreateType { .. }
            | Statement::Pragma { .. }
            | Statement::LockTables { .. }
            | Statement::UnlockTables
            | Statement::Unload { .. }
            | Statement::Load { .. }
            | Statement::Directory { .. } => {}
        }
        pass.post_statement(self)?;
        Ok(())
    }
}
impl<P: AstMutator> VisitMut<P> for SetExpr {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_set_expr(self)?;
        match self {
            SetExpr::Select(s) => s.visit_mut(pass)?,
            SetExpr::Query(q) => q.visit_mut(pass)?,
            SetExpr::SetOperation { left, right, .. } => {
                left.visit_mut(pass)?;
                right.visit_mut(pass)?;
            }
            SetExpr::Values(values) => {
                for v in values.rows.iter_mut().flat_map(|r| r.iter_mut()) {
                    v.visit_mut(pass)?;
                }
            }
            SetExpr::Insert(statement) | SetExpr::Update(statement) => statement.visit_mut(pass)?,
            SetExpr::Table(_) => todo!(),
        }
        pass.post_set_expr(self)
    }
}

impl<P: AstMutator> VisitMut<P> for Query {
    fn visit_mut(&mut self, pass: &mut P) -> Result<(), P::Error> {
        pass.pre_query(self)?;
        self.body.visit_mut(pass)?;
        if let Some(order_by) = self.order_by.as_mut() {
            order_by.visit_mut(pass)?;
        }
        if let Some(limit) = self.limit.as_mut() {
            limit.visit_mut(pass)?;
        }
        pass.post_query(self)
    }
}
