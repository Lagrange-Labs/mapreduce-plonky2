use std::str::FromStr;

use alloy::primitives::U256;
use anyhow::*;
use assembler::assemble_static;
use clap::{Parser, Subcommand};
use log::Level;
use parsil::queries::{core_keys_for_index_tree, core_keys_for_row_tree};
use ryhope::{tree::sbbst::NodeIdx, Epoch};
use sqlparser::ast::Query;
use symbols::{ContextProvider, FileContextProvider};
use utils::{parse_and_validate, ParsilSettings, PlaceholderSettings};
use verifiable_db::query::universal_circuit::universal_circuit_inputs::Placeholders;
use visitor::AstMutator;

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
        #[arg()]
        request: String,
        #[arg(long)]
        lo_sec: bool,
        #[arg(long)]
        hi_sec: bool,
        #[arg(long)]
        to_keys: bool,
    },
    Core {
        request: String,

        #[arg(short = 'E', long)]
        /// The epoch at which to run the query
        epoch: Epoch,

        #[arg(short = 'm', long)]
        /// Primary index lower bound
        min_block: i64,

        #[arg(short = 'M', long)]
        /// Primary index upper bound
        max_block: i64,
    },
}

#[derive(Subcommand)]
enum QueryKind {
    Execute,
    Keys,
}

fn prepare<C: ContextProvider>(settings: &ParsilSettings<C>, query: &str) -> Result<Query> {
    let mut query = parser::parse(settings, query)?;
    expand::expand(&mut query);
    Ok(query)
}

fn main() -> Result<()> {
    let args = Args::parse();
    stderrlog::new().verbosity(Level::Debug).init().unwrap();
    let settings = ParsilSettings {
        context: FileContextProvider::from_file("tests/context.json")?,
        placeholders: PlaceholderSettings::with_freestanding(3),
    };

    match args.command {
        Command::Debug { request } => {
            let mut query = parse_and_validate(&request, &settings)?;
            println!("Query string:\n{}", &request);
            if args.verbose {
                println!("{:#?}", query);
            }
            println!("Final query:\n{}", query);
        }
        Command::Circuit { request } => {
            let mut query = parse_and_validate(&request, &settings)?;
            assembler::validate(&query, &settings)?;
            let circuit = assemble_static(&query, &settings)?;
            println!("Statically assembled circuit PIs:\n{circuit:#?}");
        }
        Command::Query { request, kind } => {
            let mut query = parse_and_validate(&request, &settings)?;
            match kind {
                QueryKind::Execute => {
                    let mut translated = executor::generate_query_execution(&mut query, &settings)?;
                    println!("{}", translated.query.to_display());
                }
                QueryKind::Keys => {
                    let mut translated = executor::generate_query_keys(&mut query, &settings)?;
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
            let mut q = isolator::isolate_with(&mut query, &settings, lo_sec, hi_sec)?;
            if to_keys {
                let mut q = executor::generate_query_keys(&mut q, &settings)?;
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
        } => {
            let mut query = parse_and_validate(&request, &settings)?;
            let query_index =
                core_keys_for_index_tree(epoch, (min_block as NodeIdx, max_block as NodeIdx))?;
            // let query_row = core_keys_for_row_tree(
            //     qeury,
            //     &settings,
            //     (min_block as NodeIdx, max_block as NodeIdx),
            // )?;
            println!("INDEX TREE: {query_index}");
        }
    }

    Ok(())
}
