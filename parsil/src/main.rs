use anyhow::*;
use clap::{Parser, Subcommand};
use parsil::prepare;
use symbols::FileContextProvider;

mod execute;
mod expand;
mod inject;
mod parser;
mod symbols;
mod validate;

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
    Debug {},
    Execute {},
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Debug {} => {
            println!("Query string:\n{}", &args.request);
            let query = prepare(&args.request)?;
            if args.verbose {
                println!("{:#?}", query);
            }
            println!("Final query:\n{}", query);
        }
        Command::Execute {} => {
            let ctx = FileContextProvider::from_file("tests/context.json")?;
            let query = prepare(&args.request)?;
            execute::execute(&query, ctx)?;
        }
    }

    Ok(())
}
