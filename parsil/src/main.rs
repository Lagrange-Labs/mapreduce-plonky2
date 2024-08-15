use anyhow::*;
use clap::{Parser, Subcommand};
use log::Level;
use sqlparser::ast::Query;
use symbols::FileContextProvider;
use utils::{ParsingSettings, PlaceholderRegister};

mod errors;
mod executor;
mod expand;
mod parser;
mod resolve;
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

fn prepare(settings: ParsingSettings, query: &str) -> Result<Query> {
    let mut query = parser::parse(settings, query)?;
    expand::expand(&mut query);
    Ok(query)
}

fn main() -> Result<()> {
    let args = Args::parse();
    stderrlog::new().verbosity(Level::Debug).init().unwrap();
    let settings = ParsingSettings {
        placeholders: PlaceholderRegister::default(3),
    };

    match args.command {
        Command::Debug {} => {
            println!("Query string:\n{}", &args.request);
            let query = prepare(settings, &args.request)?;
            if args.verbose {
                println!("{:#?}", query);
            }
            println!("Final query:\n{}", query);
        }
        Command::Circuit {} => {
            let ctx = FileContextProvider::from_file("tests/context.json")?;
            let query = prepare(settings.clone(), &args.request)?;
            resolve::resolve(&query, ctx, settings)?;
        }
        Command::Query { kind } => {
            let ctx = FileContextProvider::from_file("tests/context.json")?;
            let query = prepare(settings, &args.request)?;
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
