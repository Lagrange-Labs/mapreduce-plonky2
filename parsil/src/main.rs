use std::str::FromStr;

use alloy::primitives::U256;
use anyhow::*;
use clap::{Parser, Subcommand};
use log::Level;
use sqlparser::ast::Query;
use symbols::{ContextProvider, FileContextProvider};
use utils::{parse_and_validate, ParsilSettings, PlaceholderSettings};
use verifiable_db::query::universal_circuit::universal_circuit_inputs::Placeholders;

mod assembler;
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
        }
        Command::Query { request, kind } => {
            let mut query = parse_and_validate(&request, &settings)?;
            match kind {
                QueryKind::Execute => {
                    let translated = executor::generate_query_execution(&mut query, &settings)?;

                    println!("{}", translated.query);
                    println!("placeholders mapping: {:?}", translated.placeholder_mapping);
                }
                QueryKind::Keys => {
                    println!("{}", executor::generate_query_keys(&mut query, &settings)?)
                }
            }
        }
        Command::Bracket {
            table,
            block,
            lo_secondary,
            hi_secondary,
        } => {
            let r = executor::bracket_secondary_index(
                &table,
                &settings,
                block,
                U256::from_str(&lo_secondary).unwrap(),
                U256::from_str(&hi_secondary).unwrap(),
            );

            println!("{}", r.0.unwrap_or("nothing".into()));
            println!("{}", r.1.unwrap_or("nothing".into()));
        }
        Command::Isolate {
            request,
            lo_sec,
            hi_sec,
        } => {
            let mut query = parse_and_validate(&request, &settings)?;
            let q = isolator::isolate_with(&mut query, &settings, lo_sec, hi_sec)?;
            println!("{q}");
        }
    }

    Ok(())
}
