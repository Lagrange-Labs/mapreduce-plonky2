use std::io::Write;

use anyhow::*;
use colored::Colorize;
use dialoguer::{console, theme::ColorfulTheme, FuzzySelect, Input};
use ryhope::{
    storage::{FromSettings, PayloadStorage, RoEpochKvStorage, TransactionalStorage, TreeStorage},
    tree::{MutableTree, TreeTopology},
    Epoch, MerkleTreeKvDb, NodePayload,
};
use tabled::{builder::Builder, settings::Style};

pub(crate) trait PayloadFormatter<V: std::fmt::Debug> {
    fn pretty_payload(&self, payload: &V) -> String {
        format!("{payload:?}")
    }

    fn settings(&mut self, tty: &mut console::Term) -> Result<()> {
        write!(tty, "no settings for payload formatter").unwrap();
        Ok(())
    }
}

pub(crate) struct Repl<
    T: TreeTopology + MutableTree,
    V: NodePayload + Send + Sync,
    S: TransactionalStorage
        + TreeStorage<T>
        + PayloadStorage<T::Key, V>
        + FromSettings<T::State>
        + Send
        + Sync,
    F: PayloadFormatter<V>,
> {
    current_key: T::Key,
    current_epoch: Epoch,
    db: MerkleTreeKvDb<T, V, S>,
    tty: console::Term,
    payload_fmt: F,
}
impl<
        T: TreeTopology + MutableTree,
        V: NodePayload + Send + Sync,
        S: TransactionalStorage
            + TreeStorage<T>
            + PayloadStorage<T::Key, V>
            + FromSettings<T::State>
            + Send
            + Sync,
        F: PayloadFormatter<V>,
    > Repl<T, V, S, F>
{
    pub async fn new(db: MerkleTreeKvDb<T, V, S>, payload_fmt: F) -> Result<Self> {
        let current_key = db.root().await.ok_or(anyhow!("tree is empty"))?;
        let current_epoch = db.current_epoch();

        Ok(Self {
            current_key,
            current_epoch,
            db,
            tty: console::Term::stdout(),
            payload_fmt,
        })
    }

    async fn headline(&mut self) {
        writeln!(
            self.tty,
            "\n\ncurrent key: {} - epoch: {} - {} nodes",
            format!("{:?}", self.current_key).blue(),
            self.current_epoch.to_string().blue(),
            self.db
                .view_at(self.current_epoch)
                .nodes
                .size()
                .await
                .to_string()
                .blue()
        )
        .unwrap();
    }

    async fn goto(&mut self) -> Result<()> {
        let keys = self.db.keys_at(self.current_epoch).await;
        let keys_str = keys.iter().map(|k| format!("{:?}", k)).collect::<Vec<_>>();

        if let Some(selection) = FuzzySelect::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("{} validate", "[enter]".yellow().bold()))
            .default(0)
            .items(&keys_str)
            .interact_opt()
            .unwrap()
        {
            self.current_key = keys[selection].to_owned();
        }
        Ok(())
    }

    async fn travel(&mut self) -> Result<()> {
        loop {
            let epoch: Epoch = Input::new().with_prompt("target epoch:").interact_text()?;

            if epoch < self.db.initial_epoch() {
                bail!(
                    "epoch `{}` is older than initial epoch `{}`",
                    epoch,
                    self.db.initial_epoch()
                );
            }
            if epoch > self.db.current_epoch() {
                bail!(
                    "epoch `{}` is newer than latest epoch `{}`",
                    epoch,
                    self.db.current_epoch()
                );
            }

            self.current_epoch = epoch;
            return Ok(());
        }
    }

    async fn goto_parent(&mut self) -> Result<()> {
        if let Some(parent) = self
            .db
            .node_context_at(&self.current_key, self.current_epoch)
            .await
            .and_then(|ctx| ctx.parent)
        {
            self.current_key = parent.to_owned();
        } else {
            bail!("no parent for current key");
        }
        Ok(())
    }

    async fn goto_left(&mut self) -> Result<()> {
        if let Some(left) = self
            .db
            .node_context_at(&self.current_key, self.current_epoch)
            .await
            .and_then(|ctx| ctx.left)
        {
            self.current_key = left.to_owned();
        } else {
            bail!("no left child for current key");
        }
        Ok(())
    }

    async fn goto_right(&mut self) -> Result<()> {
        if let Some(right) = self
            .db
            .node_context_at(&self.current_key, self.current_epoch)
            .await
            .and_then(|ctx| ctx.right)
        {
            self.current_key = right.to_owned();
        } else {
            bail!("no right child for current key");
        }
        Ok(())
    }

    async fn context(&mut self) -> Result<()> {
        if let Some(context) = self
            .db
            .node_context_at(&self.current_key, self.current_epoch)
            .await
        {
            writeln!(self.tty, "{}", "=== Current Node ===".magenta().bold()).unwrap();
            writeln!(self.tty, "{}{:?}", "Key: ".white().bold(), self.current_key).unwrap();
            writeln!(
                self.tty,
                "{}\n{}",
                "Payload:".white().bold(),
                self.payload_fmt.pretty_payload(
                    &self
                        .db
                        .fetch_at(&self.current_key, self.current_epoch)
                        .await
                )
            )
            .unwrap();

            if let Some(left) = context.left.as_ref() {
                writeln!(self.tty, "{}", "=== Left child ===".magenta().bold()).unwrap();
                writeln!(self.tty, "{}{:?}", "Key: ".white().bold(), left).unwrap();
                writeln!(
                    self.tty,
                    "{}\n{}",
                    "Payload:".white().bold(),
                    self.payload_fmt
                        .pretty_payload(&self.db.fetch_at(left, self.current_epoch).await)
                )
                .unwrap();
            }

            if let Some(right) = context.right.as_ref() {
                writeln!(self.tty, "{}", "=== Right child ===".magenta().bold()).unwrap();
                writeln!(self.tty, "{}{:?}", "Key: ".white().bold(), right).unwrap();
                writeln!(
                    self.tty,
                    "{}\n{}",
                    "Payload:".white().bold(),
                    self.payload_fmt
                        .pretty_payload(&self.db.fetch_at(right, self.current_epoch).await)
                )
                .unwrap();
            }
        } else {
            bail!(
                "{:?} does not have a context at {}",
                self.current_key,
                self.current_epoch
            )
        }
        Ok(())
    }

    async fn view_table(&mut self) -> Result<()> {
        let mut builder = Builder::default();
        builder.push_record(vec![
            "key".magenta().bold().to_string(),
            "payload".magenta().bold().to_string(),
        ]);
        for k in self.db.keys_at(self.current_epoch).await {
            let payload = self.db.fetch_at(&k, self.current_epoch).await;
            builder.push_record(vec![
                format!("{:?}", k),
                self.payload_fmt.pretty_payload(&payload),
            ]);
        }
        let mut table = builder.build();
        table.with(Style::blank());
        write!(self.tty, "{}", table).unwrap();
        Ok(())
    }

    fn settings(&mut self) -> Result<()> {
        loop {
            writeln!(
                self.tty,
                "\n{} {}ayload view - {}uit",
                "Settings".white().bold(),
                "[p]".yellow().bold(),
                "[q]".yellow().bold(),
            )
            .unwrap();

            if let Err(e) = match self.tty.read_char().unwrap() {
                'p' => self.payload_fmt.settings(&mut self.tty),
                'q' => return Ok(()),
                _ => Ok(()),
            } {
                write!(self.tty, "{}", e.to_string().red()).unwrap();
            }
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            self.headline().await;
            writeln!(
                self.tty,
                "{}ontext - goto {}ey/{}arent/{}eft/{}ight - travel to {}poch - view as {}able - {}ettings - {}uit",
                "[c]".yellow().bold(),
                "[k]".yellow().bold(),
                "[p]".yellow().bold(),
                "[l]".yellow().bold(),
                "[r]".yellow().bold(),
                "[e]".yellow().bold(),
                "[t]".yellow().bold(),
                "[s]".yellow().bold(),
                "[q]".red().bold(),
            )?;
            if let Err(e) = match self.tty.read_char().unwrap() {
                'k' => self.goto().await,
                'p' => self.goto_parent().await,
                'l' => self.goto_left().await,
                'r' => self.goto_right().await,
                'e' => self.travel().await,
                'c' => self.context().await,
                't' => self.view_table().await,
                's' => self.settings(),
                'q' => return Ok(()),
                _ => Ok(()),
            } {
                write!(self.tty, "{}", e.to_string().red()).unwrap();
            }
        }
    }
}
