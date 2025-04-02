use anyhow::{anyhow, bail};
use colored::Colorize;
use dialoguer::{console, theme::ColorfulTheme, FuzzySelect, Input};
use itertools::Itertools;
use ryhope::{
    storage::{
        FromSettings, MetaOperations, PayloadStorage, RoEpochKvStorage, TransactionalStorage,
        TreeStorage,
    },
    tree::{MutableTree, PrintableTree, TreeTopology},
    Epoch, MerkleTreeKvDb, NodePayload,
};
use std::io::Write;
use tabled::{builder::Builder, settings::Style};

pub(crate) trait PayloadFormatter<V: std::fmt::Debug> {
    fn pretty_payload(&self, payload: &V) -> String {
        format!("{payload:?}")
    }

    fn settings(&mut self, tty: &mut console::Term) -> anyhow::Result<()> {
        write!(tty, "no settings for payload formatter").unwrap();
        Ok(())
    }
}

fn menu(tty: &mut console::Term, title: &str, choices: &[(char, &str)]) -> Option<char> {
    let prompt = format!(
        "{}: {} - {}uit",
        title.white().bold(),
        choices
            .iter()
            .map(|(trigger, rest)| format!("{}{rest}", format!("[{trigger}]").yellow().bold()))
            .join(" - "),
        "[q]".red().bold(),
    );
    loop {
        writeln!(tty, "{}", prompt).unwrap();
        match tty.read_char().unwrap() {
            x if choices.iter().any(|(trigger, _)| *trigger == x) => return Some(x),
            'q' => return None,
            _ => {}
        }
    }
}

pub(crate) struct Repl<
    T: TreeTopology + MutableTree + PrintableTree,
    V: NodePayload + Send + Sync,
    S: TransactionalStorage
        + TreeStorage<T>
        + PayloadStorage<T::Key, V>
        + FromSettings<T::State>
        + MetaOperations<T, V>
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
        T: TreeTopology + MutableTree + PrintableTree,
        V: NodePayload + Send + Sync,
        S: TransactionalStorage
            + TreeStorage<T>
            + PayloadStorage<T::Key, V>
            + FromSettings<T::State>
            + MetaOperations<T, V>
            + Send
            + Sync,
        F: PayloadFormatter<V>,
    > Repl<T, V, S, F>
{
    pub async fn new(db: MerkleTreeKvDb<T, V, S>, payload_fmt: F) -> anyhow::Result<Self> {
        let current_key = db.root().await?.ok_or(anyhow!("tree is empty"))?;
        let current_epoch = db.current_epoch().await;

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
                .unwrap()
                .to_string()
                .blue()
        )
        .unwrap();
    }

    pub async fn set_epoch(&mut self, epoch: Epoch) -> anyhow::Result<()> {
        let initial_epoch = self.db.initial_epoch().await;
        anyhow::ensure!(
            epoch >= initial_epoch,
            "epoch `{}` is older than initial epoch `{}`",
            epoch,
            initial_epoch
        );

        let current_epoch = self.db.current_epoch().await;
        anyhow::ensure!(
            epoch <= current_epoch,
            "epoch `{}` is newer than latest epoch `{}`",
            epoch,
            current_epoch
        );

        self.current_epoch = epoch;
        Ok(())
    }

    async fn select_key(&self) -> Option<T::Key> {
        let keys = self.db.keys_at(self.current_epoch).await;
        let keys_str = keys.iter().map(|k| format!("{:?}", k)).collect::<Vec<_>>();

        FuzzySelect::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("{} validate", "[enter]".yellow().bold()))
            .default(0)
            .items(&keys_str)
            .interact_opt()
            .unwrap()
            .map(|i| keys[i].clone())
    }

    async fn goto(&mut self) -> anyhow::Result<()> {
        if let Some(new_key) = self.select_key().await {
            self.current_key = new_key;
        }
        Ok(())
    }

    async fn travel(&mut self) -> anyhow::Result<()> {
        loop {
            let epoch: Epoch = Input::new().with_prompt("target epoch:").interact_text()?;

            self.set_epoch(epoch).await?;
        }
    }

    async fn goto_parent(&mut self) -> anyhow::Result<()> {
        if let Some(parent) = self
            .db
            .node_context_at(&self.current_key, self.current_epoch)
            .await?
            .and_then(|ctx| ctx.parent)
        {
            self.current_key = parent.to_owned();
        } else {
            bail!("no parent for current key");
        }
        Ok(())
    }

    async fn goto_left(&mut self) -> anyhow::Result<()> {
        if let Some(left) = self
            .db
            .node_context_at(&self.current_key, self.current_epoch)
            .await?
            .and_then(|ctx| ctx.left)
        {
            self.current_key = left.to_owned();
        } else {
            bail!("no left child for current key");
        }
        Ok(())
    }

    async fn goto_right(&mut self) -> anyhow::Result<()> {
        if let Some(right) = self
            .db
            .node_context_at(&self.current_key, self.current_epoch)
            .await?
            .and_then(|ctx| ctx.right)
        {
            self.current_key = right.to_owned();
        } else {
            bail!("no right child for current key");
        }
        Ok(())
    }

    async fn context(&mut self) -> anyhow::Result<()> {
        if let Some(context) = self
            .db
            .node_context_at(&self.current_key, self.current_epoch)
            .await?
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
                        .try_fetch_at(&self.current_key, self.current_epoch)
                        .await?
                        .unwrap()
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
                    self.payload_fmt.pretty_payload(
                        &self
                            .db
                            .try_fetch_at(left, self.current_epoch)
                            .await?
                            .unwrap()
                    )
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
                    self.payload_fmt.pretty_payload(
                        &self
                            .db
                            .try_fetch_at(right, self.current_epoch)
                            .await?
                            .unwrap()
                    )
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

    async fn view_table(&mut self) -> anyhow::Result<()> {
        let mut builder = Builder::default();
        builder.push_record(vec![
            "key".magenta().bold().to_string(),
            "payload".magenta().bold().to_string(),
        ]);
        for k in self.db.keys_at(self.current_epoch).await {
            let payload = self.db.try_fetch_at(&k, self.current_epoch).await?.unwrap();
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

    async fn view_tree(&mut self) -> anyhow::Result<()> {
        if let Some(choice) = menu(
            &mut self.tty,
            "from",
            &[('c', "urrent"), ('r', "oot"), ('k', "ey")],
        ) {
            if let Some(root) = match choice {
                'c' => Some(self.current_key.clone()),
                'r' => self.db.root_at(self.current_epoch).await?,
                'k' => self.select_key().await,
                _ => unreachable!(),
            } {
                write!(
                    self.tty,
                    "\n{}",
                    self.db
                        .tree()
                        .subtree_to_string(&self.db.view_at(self.current_epoch), &root)
                        .await
                )
                .unwrap();
            } else {
                write!(self.tty, "Empty tree").unwrap();
            }
        }

        Ok(())
    }

    async fn tree_operations(&mut self) -> anyhow::Result<()> {
        if let Some(choice) = menu(&mut self.tty, "from", &[('l', "ineage")]) {
            match choice {
                'l' => {
                    if let Some(key) = self.select_key().await {
                        let ascendance = self
                            .db
                            .tree()
                            .lineage(&key, &self.db.view_at(self.current_epoch))
                            .await;
                        println!("{key:?} -> {:?}", ascendance);

                        println!()
                    }
                }
                _ => unreachable!(),
            }
        }

        Ok(())
    }

    fn settings(&mut self) -> anyhow::Result<()> {
        if let Some(choice) = menu(&mut self.tty, "settings", &[('p', "ayload view")]) {
            if let Err(e) = match choice {
                'p' => self.payload_fmt.settings(&mut self.tty),
                _ => unreachable!(),
            } {
                write!(self.tty, "{}", e.to_string().red()).unwrap();
            }
        }

        Ok(())
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            self.headline().await;
            writeln!(
                self.tty,
                "{}ontext - goto {}ey/{}arent/{}eft/{}ight - travel to {}poch - view as {}able/{}ree - {}perations - {}ettings - {}uit",
                "[c]".yellow().bold(),
                "[k]".yellow().bold(),
                "[p]".yellow().bold(),
                "[l]".yellow().bold(),
                "[r]".yellow().bold(),
                "[e]".yellow().bold(),
                "[t]".yellow().bold(),
                "[T]".yellow().bold(),
                "[o]".yellow().bold(),
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
                'T' => self.view_tree().await,
                'o' => self.tree_operations().await,
                's' => self.settings(),
                'q' => return Ok(()),
                _ => Ok(()),
            } {
                write!(self.tty, "{}", e.to_string().red()).unwrap();
            }
        }
    }
}
