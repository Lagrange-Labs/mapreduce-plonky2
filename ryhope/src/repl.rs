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

pub(crate) struct Repl<
    T: TreeTopology + MutableTree,
    V: NodePayload + Send + Sync,
    S: TransactionalStorage
        + TreeStorage<T>
        + PayloadStorage<T::Key, V>
        + FromSettings<T::State>
        + Send
        + Sync,
> {
    current_key: T::Key,
    current_epoch: Epoch,
    db: MerkleTreeKvDb<T, V, S>,
    tty: console::Term,
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
    > Repl<T, V, S>
{
    pub async fn new(db: MerkleTreeKvDb<T, V, S>) -> Result<Self> {
        let current_key = db.root().await.ok_or(anyhow!("tree is empty"))?;
        let current_epoch = db.current_epoch();

        Ok(Self {
            current_key,
            current_epoch,
            db,
            tty: console::Term::stdout(),
        })
    }

    async fn headline(&mut self) {
        writeln!(
            self.tty,
            "\ncurrent key: {} - epoch: {} - {} nodes",
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
            .with_prompt("Go to")
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
            let epoch: Epoch = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("target epoch:")
                .interact_text()?;

            if epoch < 0 || epoch > self.db.current_epoch() {
                bail!("erroneous epoch {}", epoch);
            } else {
                self.current_epoch = epoch;
                return Ok(());
            }
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
            writeln!(self.tty, "===== Current node:").unwrap();
            writeln!(self.tty, "    key: {:?}", self.current_key).unwrap();
            writeln!(
                self.tty,
                "    payload: {:?}",
                self.db
                    .fetch_at(&self.current_key, self.current_epoch)
                    .await
            )
            .unwrap();

            if let Some(left) = context.left.as_ref() {
                writeln!(self.tty, "===== Left child:").unwrap();
                writeln!(self.tty, "    key: {:?}", left).unwrap();
                writeln!(
                    self.tty,
                    "    payload: {:?}",
                    self.db.fetch_at(left, self.current_epoch).await
                )
                .unwrap();
            }

            if let Some(right) = context.right.as_ref() {
                writeln!(self.tty, "===== Right child:").unwrap();
                writeln!(self.tty, "    key: {:?}", right).unwrap();
                writeln!(
                    self.tty,
                    "    payload: {:?}",
                    self.db.fetch_at(right, self.current_epoch).await
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
        builder.push_record(vec!["key", "payload"]);
        for k in self.db.keys_at(self.current_epoch).await {
            let payload = self.db.fetch_at(&k, self.current_epoch).await;
            builder.push_record(vec![format!("{:?}", k), payload.view()]);
        }
        let mut table = builder.build();
        table.with(Style::sharp());
        write!(self.tty, "{}", table).unwrap();
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            self.headline().await;
            writeln!(
                self.tty,
                "[c]ontext - goto {}ey/{}arent/{}eft/{}ight - travel to {}poch - view as {}able - {}uit",
                "[k]".yellow().bold(),
                "[p]".yellow().bold(),
                "[l]".yellow().bold(),
                "[r]".yellow().bold(),
                "[e]".yellow().bold(),
                "[t]".yellow().bold(),
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
                'q' => return Ok(()),
                _ => Ok(()),
            } {
                write!(self.tty, "{}", e.to_string().red()).unwrap();
            }
        }
    }
}
