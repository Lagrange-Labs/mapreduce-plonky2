use anyhow::*;
use clap::{Parser, Subcommand};
use index::RowPayloadFormatter;
use mp2_v1::indexing::{
    block::BlockPrimaryIndex,
    row::{RowPayload, RowTree},
};
use repl::Repl;
use ryhope::{
    storage::pgsql::{PgsqlStorage, SqlServerConnection, SqlStorageSettings, ToFromBytea},
    tree::scapegoat,
    InitSettings, MerkleTreeKvDb,
};
use serde::Serialize;

mod index;
mod repl;

type MerkleRowTree = MerkleTreeKvDb<
    RowTree,
    RowPayload<BlockPrimaryIndex>,
    PgsqlStorage<RowTree, RowPayload<BlockPrimaryIndex>>,
>;

#[derive(Parser)]
#[command()]
struct Args {
    #[arg(short = 'H', long, default_value = "localhost")]
    /// How to connect to the database
    db_host: String,

    #[arg(short = 'W', long)]
    /// The DB user password, if any
    db_password: Option<String>,

    #[arg(short = 'D', long, default_value = "storage")]
    /// The database to open
    db_name: String,

    #[arg(short = 'P', long, default_value = "5432")]
    /// The port PostgreSQL listens on
    db_port: u16,

    #[arg(short = 'T', long)]
    /// The table storing the tree
    db_table: String,

    #[command(subcommand)]
    /// The type of tree to load from the database
    tree_type: TreeReader,
}

#[derive(Subcommand)]
enum TreeReader {
    IndexTree {
        #[arg(short = 'C', long)]
        /// A comma-separed list of `id=name` pairs mapping columns IDs to user-facing names
        column_names: Option<String>,
    },
}

type K = Vec<u8>;
type Tree = scapegoat::Tree<K>;
type V = serde_json::Value;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Hash, Debug)]
// #[serde(from = "Vec<u8>")]
struct Key {
    k: Vec<u8>,
}

impl ToFromBytea for Key {
    fn to_bytea(&self) -> Vec<u8> {
        self.k.clone()
    }

    fn from_bytea(k: Vec<u8>) -> Self {
        Self { k }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let db_uri = format!(
        "host={} dbname={} port={}{}",
        args.db_host,
        args.db_name,
        args.db_port,
        args.db_password
            .map(|p| format!(" password={p}"))
            .unwrap_or_default()
    );

    let tree_db = MerkleRowTree::new(
        InitSettings::MustExist,
        SqlStorageSettings {
            source: SqlServerConnection::NewConnection(db_uri),
            table: args.db_table,
        },
    )
    .await?;

    match args.tree_type {
        TreeReader::IndexTree { column_names } => {
            let payload_fmt = if let Some(columns_name) = column_names.as_ref() {
                RowPayloadFormatter::from_string(columns_name)?
            } else {
                RowPayloadFormatter::new()
            };
            let mut repl = Repl::new(tree_db, payload_fmt).await?;
            repl.run().await
        }
    }
}
