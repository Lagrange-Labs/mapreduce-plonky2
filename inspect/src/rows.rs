use anyhow::*;
use colored::Colorize;
use ryhope::{storage::pgsql::PgsqlStorage, MerkleTreeKvDb};
use std::collections::HashMap;

use dialoguer::MultiSelect;
use itertools::Itertools;
use mp2_v1::indexing::{
    block::BlockPrimaryIndex,
    row::{RowPayload, RowTree},
    ColumnID,
};
use tabled::{builder::Builder, settings::Style};

use crate::repl::PayloadFormatter;

pub(crate) type RowDb = MerkleTreeKvDb<
    RowTree,
    RowPayload<BlockPrimaryIndex>,
    PgsqlStorage<RowTree, RowPayload<BlockPrimaryIndex>, true>,
>;

struct RowPayloadFormatterDisplay {
    value: bool,
    proved_at: bool,
    hash: bool,
}
impl std::default::Default for RowPayloadFormatterDisplay {
    fn default() -> Self {
        Self {
            value: true,
            proved_at: false,
            hash: false,
        }
    }
}
impl RowPayloadFormatterDisplay {
    fn outer_header(&self) -> Vec<String> {
        let mut r = vec![];
        if self.hash {
            r.push("hash".white().bold().to_string());
        }
        r.push("table view".white().bold().to_string());
        r
    }

    fn inner_header(&self) -> Vec<String> {
        let mut r = vec![
            "2 Idx".white().bold().to_string(),
            "name".white().bold().to_string(),
        ];
        if self.value {
            r.push("value".white().bold().to_string());
        }
        if self.proved_at {
            r.push("proved at".white().bold().to_string());
        }
        r
    }
}

pub(crate) struct RowPayloadFormatter {
    display: RowPayloadFormatterDisplay,
    column_names: HashMap<ColumnID, String>,
}
impl RowPayloadFormatter {
    pub fn new() -> Self {
        Self {
            display: Default::default(),
            column_names: Default::default(),
        }
    }

    pub fn from_string(input: &str) -> Result<Self> {
        let mut column_names = HashMap::new();
        for ss in input.split(',') {
            let mut s = ss.split('=');
            let column_id = s
                .next()
                .ok_or_else(|| anyhow!("`{ss}`: column ID not found"))
                .and_then(|x| {
                    x.parse::<ColumnID>()
                        .map_err(|e| anyhow!("`{ss}`: not a column ID: {e}"))
                })?;

            let column_name = s
                .next()
                .ok_or_else(|| anyhow!("`{ss}`: column name not found"))?;

            column_names.insert(column_id, column_name.to_string());
        }

        Ok(Self {
            display: Default::default(),
            column_names,
        })
    }
}

impl<T: Default + Eq + std::hash::Hash + std::fmt::Debug> PayloadFormatter<RowPayload<T>>
    for RowPayloadFormatter
{
    fn pretty_payload(&self, p: &RowPayload<T>) -> String {
        let mut inner_table_b = Builder::default();
        inner_table_b.push_record(self.display.inner_header());
        for (column_id, v) in p.cells.iter().sorted_by_key(|(k, _)| k.to_owned()) {
            let mut r = vec![
                if *column_id == p.secondary_index_column {
                    "*"
                } else {
                    ""
                }
                .to_string(),
                self.column_names
                    .get(column_id)
                    .cloned()
                    .unwrap_or(column_id.to_string()),
            ];
            if self.display.value {
                r.push(format!("0x{:x}", v.value));
            }
            if self.display.proved_at {
                r.push(format!("{:?}", v.primary));
            }
            inner_table_b.push_record(r)
        }
        let mut inner_table = inner_table_b.build();
        inner_table.with(Style::sharp());

        let mut outer_table_b = Builder::default();
        outer_table_b.push_record(self.display.outer_header());
        let mut outer_content = Vec::new();
        if self.display.hash {
            outer_content.push(hex::encode(&p.hash));
        }
        outer_content.push(inner_table.to_string());
        outer_table_b.push_record(outer_content);

        let mut outer_table = outer_table_b.build();
        outer_table.with(Style::blank());
        outer_table.to_string()
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
                ("proved at", self.display.proved_at),
                ("hash", self.display.proved_at),
            ])
            .interact_opt()
            .unwrap()
        {
            self.display.value = selection.contains(&0);
            self.display.proved_at = selection.contains(&1);
            self.display.hash = selection.contains(&2);
        }

        Ok(())
    }
}
