use anyhow::*;
use clap::Parser;
use ryhope::MerkleTreeKvDb;
use tokio_postgres::NoTls;

#[derive(Parser)]
#[command()]
struct Args {
    #[arg(short = 'H', long, default_value = "localhost")]
    /// How to connect to the database
    db_host: String,

    #[arg(short = 'W', long)]
    /// The DB user password, if any
    db_password: String,

    #[arg(short = 'D', long, default_value = "storage")]
    /// The database to open
    db_name: String,

    #[arg(short = 'P', long, default_value = "5432")]
    /// The port PostgreSQL listens on
    db_port: u16,

    #[arg(short = 'T', long)]
    /// The table storing the tree
    db_table: String,

    #[arg(short='t', long="tree", value_parser=["sbbst", "scapegoat"])]
    /// The type of tree to load from the database
    tree_type: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let db_uri = format!(
        "host={} dbname={} port={} password='{}' ",
        args.db_host, args.db_name, args.db_port, args.db_password
    );

    let (client, connection) = tokio_postgres::connect(&db_uri, NoTls).await?;
    println!("Coucou lol");

    Ok(())
}
