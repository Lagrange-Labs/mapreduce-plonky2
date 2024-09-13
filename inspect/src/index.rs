use anyhow::*;
use colored::Colorize;
use dialoguer::MultiSelect;
use mp2_v1::indexing::{
    block::{BlockPrimaryIndex, BlockTree},
    index::IndexNode,
    LagrangeNode,
};
use ryhope::{storage::pgsql::PgsqlStorage, MerkleTreeKvDb};
use tabled::{builder::Builder, settings::Style};

use crate::repl::PayloadFormatter;

pub(crate) type IndexDb = MerkleTreeKvDb<
    BlockTree,
    IndexNode<BlockPrimaryIndex>,
    PgsqlStorage<BlockTree, IndexNode<BlockPrimaryIndex>>,
>;

struct IndexPayloadFormatterDisplay {
    value: bool,
    row_tree_root_key: bool,
    row_tree_root_hash: bool,
    hash: bool,
    min: bool,
    max: bool,
}
impl std::default::Default for IndexPayloadFormatterDisplay {
    fn default() -> Self {
        Self {
            value: false,
            hash: true,
            min: true,
            max: true,
            row_tree_root_key: false,
            row_tree_root_hash: false,
        }
    }
}
impl IndexPayloadFormatterDisplay {
    fn header(&self) -> Vec<String> {
        let mut r = vec![];
        if self.value {
            r.push("value".white().bold().to_string());
        }
        if self.hash {
            r.push("hash".white().bold().to_string());
        }
        if self.min {
            r.push("min".white().bold().to_string());
        }
        if self.max {
            r.push("max".white().bold().to_string());
        }
        if self.row_tree_root_key {
            r.push("R. tree root key".white().bold().to_string());
        }
        if self.row_tree_root_hash {
            r.push("R. tree root hash".white().bold().to_string());
        }
        r
    }
}

#[derive(Default)]
pub(crate) struct IndexPayloadFormatter {
    display: IndexPayloadFormatterDisplay,
}
impl PayloadFormatter<IndexNode<BlockPrimaryIndex>> for IndexPayloadFormatter {
    fn pretty_payload(&self, payload: &IndexNode<BlockPrimaryIndex>) -> String {
        let mut builder = Builder::new();
        builder.push_record(self.display.header());

        let mut r = vec![];
        if self.display.value {
            r.push(format!("0x{:x}", payload.value.0));
        }
        if self.display.hash {
            r.push(hex::encode(&payload.node_hash));
        }
        if self.display.min {
            r.push(format!("{}", payload.min()));
        }
        if self.display.max {
            r.push(format!("{}", payload.max()));
        }
        if self.display.row_tree_root_key {
            r.push(format!("{:?}", payload.row_tree_root_key));
        }
        if self.display.row_tree_root_hash {
            r.push(hex::encode(&payload.row_tree_hash));
        }
        builder.push_record(r);

        let mut table = builder.build();
        table.with(Style::blank());
        table.to_string()
    }

    fn settings(&mut self, _tty: &mut dialoguer::console::Term) -> Result<()> {
        if let Some(selection) = MultiSelect::new()
            .with_prompt(format!(
                "{} select - {} validate",
                "[space]".yellow().bold(),
                "[enter]".yellow().bold()
            ))
            .items_checked(&[
                ("value", self.display.value),
                ("hash", self.display.hash),
                ("min", self.display.min),
                ("max", self.display.max),
                ("R. tree root key", self.display.row_tree_root_key),
                ("R. tree root hash", self.display.row_tree_root_hash),
            ])
            .interact_opt()
            .unwrap()
        {
            self.display.value = selection.contains(&0);
            self.display.hash = selection.contains(&1);
            self.display.min = selection.contains(&2);
            self.display.max = selection.contains(&3);
            self.display.row_tree_root_key = selection.contains(&4);
            self.display.row_tree_root_hash = selection.contains(&5);
        }

        Ok(())
    }
}
