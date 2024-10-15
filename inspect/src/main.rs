use anyhow::*;
use clap::{Parser, Subcommand};
use index::{IndexDb, IndexPayloadFormatter};
use repl::Repl;
use rows::{RowDb, RowPayloadFormatter};
use ryhope::{
    storage::pgsql::{SqlServerConnection, SqlStorageSettings, ToFromBytea},
    Epoch, InitSettings,
};
use serde::Serialize;

mod index;
mod repl;
mod rows;

#[derive(Parser)]
#[command()]
struct Args {
    #[arg(long, default_value = "postgresql://localhost/storage")]
    /// How to connect to the database
    db_uri: String,

    #[arg(short = 'T', long)]
    /// The table storing the tree
    db_table: String,

    #[arg(short = 'E', long = "at")]
    /// If set, try to view the tree at this epoch
    epoch: Option<Epoch>,

    #[command(subcommand)]
    /// The type of tree to load from the database
    tree_type: TreeReader,
}

#[derive(Subcommand)]
enum TreeReader {
    RowTree {
        #[arg(short = 'C', long)]
        /// A comma-separed list of `id=name` pairs mapping columns IDs to user-facing names
        column_names: Option<String>,

        #[arg(short = 'D', long, conflicts_with = "column_names")]
        /// A comma-separed list of `id=name` pairs mapping columns IDs to user-facing names
        column_db: Option<String>,
    },
    IndexTree,
}

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

    match args.tree_type {
        TreeReader::RowTree {
            column_names,
            column_db,
        } => {
            let tree_db = RowDb::new(
                InitSettings::MustExist,
                SqlStorageSettings {
                    source: SqlServerConnection::NewConnection(args.db_uri.clone()),
                    table: args.db_table,
                },
            )
            .await?;

            let payload_fmt = if let Some(column_name) = column_names.as_ref() {
                RowPayloadFormatter::from_string(column_name)?
            } else if let Some(_column_db) = column_db.as_ref() {
                todo!()
            } else {
                RowPayloadFormatter::new()
            };

            let mut repl = Repl::new(tree_db, payload_fmt).await?;
            if let Some(epoch) = args.epoch {
                repl.set_epoch(epoch)?;
            }
            repl.run().await
        }
        TreeReader::IndexTree => {
            let tree_db = IndexDb::new(
                InitSettings::MustExist,
                SqlStorageSettings {
                    source: SqlServerConnection::NewConnection(args.db_uri.clone()),
                    table: args.db_table,
                },
            )
            .await?;

            let payload_fmt = IndexPayloadFormatter::default();

            let mut repl = Repl::new(tree_db, payload_fmt).await?;
            if let Some(epoch) = args.epoch {
                repl.set_epoch(epoch)?;
            }
            repl.run().await
        }
    }
}
