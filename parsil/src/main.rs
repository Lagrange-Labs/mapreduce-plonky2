use std::str::FromStr;

use alloy::primitives::U256;
use anyhow::*;
use assembler::assemble_static;
use clap::{Parser, Subcommand};
use log::Level;
use parsil::queries::{core_keys_for_index_tree, core_keys_for_row_tree};
use ryhope::{tree::sbbst::NodeIdx, UserEpoch};
use sqlparser::ast::Query;
use symbols::{ContextProvider, FileContextProvider};
use utils::{parse_and_validate, ParsilSettings, PlaceholderSettings};

mod assembler;
mod bracketer;
mod errors;
mod executor;
mod expand;
mod isolator;
mod parser;
mod placeholders;
mod symbols;
mod utils;
mod validate;
mod visitor;

#[derive(Parser)]
struct Args {
    #[arg(short = 'v', global = true)]
    verbose: bool,

    #[arg(long, short = 'L', global = true)]
    limit: Option<u32>,

    #[arg(long, short = 'O', global = true)]
    offset: Option<u32>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Displays the AST as parsed by sqlparser.
    Debug {
        #[arg()]
        request: String,
    },
    /// Generate the PIs required by the universal query circuit.
    Circuit {
        #[arg()]
        request: String,
    },
    /// Generate the queries to execute the user query of fetch the range of
    /// primary indices and key it touches.
    Query {
        #[arg()]
        request: String,

        #[command(subcommand)]
        kind: QueryKind,
    },
    /// Generate the query to bracket the secondary index values for an empty
    /// result query.
    Bracket {
        table: String,
        block: i64,
        lo_secondary: String,
        hi_secondary: String,
    },
    /// Modify the given query to neuter all WHERE clauses not related to
    /// indices.
    Isolate {
        #[arg(long, short = 'Q')]
        request: String,

        /// The lower bound of the secondary index, if any.
        #[arg(long)]
        lo_sec: Option<String>,

        /// The higher bound of the secondary index, if any.
        #[arg(long)]
        hi_sec: Option<String>,

        #[arg(long)]
        to_keys: bool,
    },
    Core {
        /// The query to execute if tree_type is "row", or the table name if
        /// tree_type is "index"
        #[arg(long, short = 'Q')]
        request: String,

        /// The epoch at which to run the query
        #[arg(short = 'E', long)]
        epoch: UserEpoch,

        /// Primary index lower bound
        #[arg(short = 'm', long)]
        min_block: i64,

        /// Primary index upper bound
        #[arg(short = 'M', long)]
        max_block: i64,

        /// The type of tree
        #[arg(long="tree", value_parser = ["row", "index"])]
        tree_type: String,
    },
}

#[derive(Subcommand)]
enum QueryKind {
    Execute,
    Keys,
}

const MAX_NUM_COLUMNS: usize = 10;
const MAX_NUM_PREDICATE_OPS: usize = 20;
const MAX_NUM_RESULT_OPS: usize = 20;
const MAX_NUM_ITEMS_PER_OUTPUT: usize = 10;
const MAX_NUM_OUTPUTS: usize = 5;

fn main() -> Result<()> {
    let args = Args::parse();
    stderrlog::new().verbosity(Level::Debug).init().unwrap();
    let settings = ParsilSettings {
        context: FileContextProvider::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_OUTPUTS,
        >::from_file("tests/context.json")?,
        placeholders: PlaceholderSettings::with_freestanding(3),
        limit: args.limit,
        offset: args.offset,
    };

    match args.command {
        Command::Debug { request } => {
            let query = parse_and_validate(&request, &settings)?;
            println!("Query string:\n{}", &request);
            if args.verbose {
                println!("{:#?}", query);
            }
            println!("Final query:\n{}", query);
        }
        Command::Circuit { request } => {
            let query = parse_and_validate(&request, &settings)?;
            assembler::validate(&query, &settings)?;
            let circuit = assemble_static(&query, &settings)?;
            println!("Statically assembled circuit PIs:\n{circuit:#?}");
        }
        Command::Query { request, kind } => {
            let mut query = parse_and_validate(&request, &settings)?;
            match kind {
                QueryKind::Execute => {
                    let translated = executor::generate_query_execution(&mut query, &settings)?;
                    println!("{}", translated.query.to_display());
                }
                QueryKind::Keys => {
                    let translated = executor::generate_query_keys(&mut query, &settings)?;
                    println!("{}", translated.query.to_display());
                }
            }
        }
        Command::Isolate {
            request,
            lo_sec,
            hi_sec,
            to_keys,
        } => {
            let mut query = parse_and_validate(&request, &settings)?;
            let mut q = isolator::isolate_with(
                &mut query,
                &settings,
                lo_sec.map(|s| U256::from_str(&s).unwrap()),
                hi_sec.map(|s| U256::from_str(&s).unwrap()),
            )?;
            if to_keys {
                let q = executor::generate_query_keys(&mut q, &settings)?;
                println!("Query: {}", q.query.to_display());
            } else {
                println!("{}", q);
            }
        }
        Command::Bracket {
            table,
            block,
            lo_secondary,
            hi_secondary,
        } => {
            let r = bracketer::_bracket_secondary_index(
                &table,
                &settings,
                block,
                &U256::from_str(&lo_secondary).unwrap(),
                &U256::from_str(&hi_secondary).unwrap(),
            );

            println!("{}", r.0.unwrap_or("nothing".into()));
            println!("{}", r.1.unwrap_or("nothing".into()));
        }
        Command::Core {
            request,
            epoch,
            min_block,
            max_block,
            tree_type,
        } => {
            let q = match tree_type.as_str() {
                "row" => {
                    todo!();
                    // core_keys_for_row_tree(
                    //     &request,
                    //     &settings,
                    //     (min_block as NodeIdx, max_block as NodeIdx),
                    //     todo!(),
                    // )?
                }
                "index" => core_keys_for_index_tree(
                    epoch,
                    (min_block as NodeIdx, max_block as NodeIdx),
                    &request,
                )?,
                _ => unreachable!(),
            };

            println!("{q}");
        }
    }

    Ok(())
}
