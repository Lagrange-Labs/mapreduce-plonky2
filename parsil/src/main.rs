use anyhow::*;
use clap::{Parser, Subcommand};
use log::Level;
use sqlparser::ast::Query;
use symbols::{ContextProvider, FileContextProvider};
use utils::{parse_and_validate, ParsilSettings, PlaceholderSettings};

mod circuit;
mod errors;
mod executor;
mod expand;
mod parser;
mod placeholders;
mod symbols;
mod utils;
mod validate;
mod visitor;

#[derive(Parser)]
struct Args {
    #[arg()]
    request: String,

    #[arg(short = 'v', global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Displays the AST as parsed by sqlparser.
    Debug {},
    /// Generate the PIs required by the universal query circuit.
    Circuit {},
    /// Generate the queries to execute the user query of fetch the range of
    /// primary indices and key it touches.
    Query {
        #[command(subcommand)]
        kind: QueryKind,
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
    let query = parse_and_validate(&args.request, &settings)?;

    match args.command {
        Command::Debug {} => {
            println!("Query string:\n{}", &args.request);
            if args.verbose {
                println!("{:#?}", query);
            }
            println!("Final query:\n{}", query);
        }
        Command::Circuit {} => {
            circuit::Assembler::validate(&query, &settings)?;
        }
        Command::Query { kind } => {
            let ctx = FileContextProvider::from_file("tests/context.json")?;
            println!(
                "{}",
                match kind {
                    QueryKind::Execute => executor::generate_query_execution(&query, ctx)?,
                    QueryKind::Keys => executor::generate_query_keys(&query, ctx)?,
                }
            );
        }
    }

    Ok(())
}
