use super::{block::BlockPrimaryIndex, cell::CellTreeKey, ColumnID};
use alloy::primitives::U256;
use anyhow::Result;
use derive_more::{Deref, From};
use hashbrown::HashMap;
use mp2_common::{
    poseidon::{empty_poseidon_hash, H},
    types::HashOutput,
    utils::ToFields,
    F,
};
use plonky2::{
    field::types::Field,
    hash::hash_types::HashOut,
    plonk::config::{GenericHashOut, Hasher},
};
use ryhope::{
    storage::pgsql::{PgsqlStorage, ToFromBytea},
    tree::scapegoat,
    MerkleTreeKvDb, NodePayload,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub type RowTree = scapegoat::Tree<RowTreeKey>;
pub type RowTreeKeyNonce = Vec<u8>;

pub type RowStorage = PgsqlStorage<RowTree, RowPayload<BlockPrimaryIndex>, true>;
pub type MerkleRowTree = MerkleTreeKvDb<RowTree, RowPayload<BlockPrimaryIndex>, RowStorage>;

pub trait ToNonce {
    fn to_nonce(&self) -> RowTreeKeyNonce;
}

/// Serialize a U256 into its decimal representation
fn u256_to_string<S: Serializer>(x: &U256, s: S) -> Result<S::Ok, S::Error> {
    // U256 defaults to decimal stringization
    s.serialize_str(&format!("{x}"))
}

/// Deserialize a U256 from its decimal representation
fn string_to_u256<'de, D>(d: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(d).and_then(|s| {
        U256::from_str_radix(&s, 10).map_err(|e| serde::de::Error::custom(e.to_string()))
    })
}

/// A unique identifier of a secondary-indexed row, from the secondary index value and an unique
/// index since secondary index does not have to be unique.
/// THis struct is kept in the JSON row as the "tree key".
#[derive(Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RowTreeKey {
    /// Value of the secondary index of the row
    pub value: U256,
    /// An value such that the pair (value,rest) is unique accross all rows
    pub rest: RowTreeKeyNonce,
}
impl std::fmt::Debug for RowTreeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:x}@{}",
            self.value,
            self.rest.iter().map(|x| x.to_string()).collect::<String>()
        )
    }
}

impl RowTreeKey {
    // Returns a row key from a value and the "nonce". Since in the row tree, multiple rows/nodes
    // can have the same value, we need an additional information such that both combine make an
    // unique identifier for the row.
    pub fn new(value: U256, rest: &[u8]) -> Self {
        Self {
            value,
            rest: rest.to_vec(),
        }
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let b = bincode::serialize(self)?;
        Ok(b)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let s = bincode::deserialize(bytes)?;
        Ok(s)
    }
}

/// CellInfo is the structure saved in the row JSON payload.
///
/// Each cell info is identified by its column ID in the CellCollection.
/// The primary information is required to be able to pinpoint each cells to its associated proof.
/// This is required to be able to snapsho, go back in time, prove multiple blocks in parallel etc.
#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CellInfo<PrimaryIndex> {
    /// Value of the cell
    #[serde(serialize_with = "u256_to_string", deserialize_with = "string_to_u256")]
    pub value: U256,
    /// The primary index under which this cell was proven to. In most cases it will be a block
    /// number.
    pub primary: PrimaryIndex,
}

impl<PrimaryIndex> CellInfo<PrimaryIndex> {
    pub fn new(value: U256, primary: PrimaryIndex) -> Self {
        Self { value, primary }
    }
}

/// A collection of cells inserted in the JSON.
///
/// IMPORTANT: This collection MUST CONTAIN the secondary index value, as first element, to easily
/// search in JSONB from the SQL. It is also important it is in an easily
/// searchable format.
#[derive(Eq, PartialEq, Deref, From, Default, Debug, Clone, Serialize, Deserialize)]
pub struct CellCollection<PrimaryIndex>(pub HashMap<ColumnID, CellInfo<PrimaryIndex>>);
impl<PrimaryIndex: PartialEq + Eq + Default + Clone> CellCollection<PrimaryIndex> {
    pub fn update_column(&mut self, id: ColumnID, cell: CellInfo<PrimaryIndex>) {
        self.0.insert(id, cell);
    }
    pub fn find_by_column(&self, id: ColumnID) -> Option<&CellInfo<PrimaryIndex>> {
        self.0.get(&id)
    }
    // take all the cells ids on both collections, take the value present in the updated one
    // if it exists, otherwise take from self.
    pub fn merge_with_update(&self, updated_cells: &Self) -> Self {
        if self == &Self::default() {
            return updated_cells.clone();
        }
        Self(
            self.0
                .iter()
                .map(|(previous_id, previous_cell)| {
                    updated_cells
                        .get(previous_id)
                        .map(|new_cell| (previous_id, new_cell))
                        .unwrap_or((previous_id, previous_cell))
                })
                .map(|(id, cell)| (*id, cell.clone()))
                .collect(),
        )
    }
}

/// An utility wrapper to pass around that connects what we put in the JSON description and
/// the actual row key used to insert in the tree
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row<PrimaryIndex: PartialEq + Eq + Default> {
    /// A key *uniquely* representing this row in the row tree.
    /// NOTE: this key is **not** the index as understood in the crypto
    /// formalization.
    pub k: RowTreeKey,
    // What is being included in the row JSON
    pub payload: RowPayload<PrimaryIndex>,
}
/// Represent a row in one of the virtual tables stored in the zkDB; which
/// encapsulates its cells and the tree they form.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RowPayload<PrimaryIndex: PartialEq + Eq + Default> {
    /// Map from column id to value
    /// This includes the secondary index value as well
    pub cells: CellCollection<PrimaryIndex>,
    /// The ID of the secondary index column.
    pub secondary_index_column: ColumnID,
    /// Storing the hash of the root of the cells tree. One could get it as well from the proof
    /// but it requires loading the proof, so when building the hashing structure it's best
    /// to keep it at hand directly.
    pub(crate) cell_root_hash: Option<HashOutput>,
    /// Information needed to retrieve the cells root proof belonging to this row
    /// From the column ID, one can search in the cell collection to find the corresponding
    /// value and primary index, necessary to fetch the corresponding proof.
    pub(crate) cell_root_column: Option<ColumnID>,
    /// Information needed to retrieve the cells root proof belonging to this row
    pub cell_root_key: CellTreeKey,
    /// Min sec. index value of the subtree below this node
    pub min: U256,
    /// Max sec. index value "  "   "       "     "    "
    pub max: U256,
    /// Hash of this node
    pub hash: HashOutput,
}

impl<PrimaryIndex: std::fmt::Debug + Clone + Default + PartialEq + Eq> RowPayload<PrimaryIndex> {
    /// Construct a row payload from
    /// * the collection of cells, which MUST include the value of the secondary index
    /// * the hash of the cells tree associated to that row
    /// * the primary index value when that cells tree root proof was generated. In most cases, the
    ///     primary value is the block index. The block would refer to the last time the cells tree
    ///     changed for that row.
    /// * The key of the root of the cells tree.
    pub fn new(
        cells: CellCollection<PrimaryIndex>,
        secondary_index: ColumnID,
        cell_tree_hash: Option<HashOutput>,
        cell_root_column: Option<ColumnID>,
        cell_root_key: CellTreeKey,
    ) -> Self {
        RowPayload {
            cells,
            secondary_index_column: secondary_index,
            cell_root_hash: cell_tree_hash,
            cell_root_column,
            cell_root_key,
            ..Default::default()
        }
    }

    pub fn column_value(&self, column_id: ColumnID) -> Option<U256> {
        self.cells.get(&column_id).map(|c| c.value)
    }
    pub fn secondary_index_value(&self) -> U256 {
        self.cells
            .get(&self.secondary_index_column)
            .unwrap_or_else(|| {
                panic!(
                    "unable to get secondary column {:?} on cells {:?}",
                    self.secondary_index_column, self.cells
                )
            })
            .value
    }
    /// Returns the primary index value under which this row is stored
    pub fn primary_index_value(&self) -> PrimaryIndex {
        self.cells[&self.secondary_index_column].primary.clone()
    }
    pub fn fetch_cell_root_info(&self) -> Option<&CellInfo<PrimaryIndex>> {
        self.cell_root_column
            .as_ref()
            .map(|column| &self.cells[column])
    }
}

impl<
        PrimaryIndex: std::fmt::Debug
            + PartialEq
            + Eq
            + Default
            + Clone
            + Sized
            + Serialize
            + for<'a> Deserialize<'a>,
    > NodePayload for RowPayload<PrimaryIndex>
{
    fn aggregate<'a, I: Iterator<Item = Option<Self>>>(&mut self, children: I) {
        let children = children.into_iter().collect::<Vec<_>>();
        assert_eq!(children.len(), 2);

        let (left_hash, right_hash) = match [&children[0], &children[1]] {
            [None, None] => {
                self.min = self.secondary_index_value();
                self.max = self.secondary_index_value();
                (*empty_poseidon_hash(), *empty_poseidon_hash())
            }
            [None, Some(right)] => {
                self.min = self.secondary_index_value();
                self.max = right.max;
                (*empty_poseidon_hash(), HashOut::from_bytes(&right.hash.0))
            }
            [Some(left), None] => {
                self.min = left.min;
                self.max = self.secondary_index_value();
                (HashOut::from_bytes(&left.hash.0), *empty_poseidon_hash())
            }
            [Some(left), Some(right)] => {
                self.min = left.min;
                self.max = right.max;
                (
                    HashOut::from_bytes(&left.hash.0),
                    HashOut::from_bytes(&right.hash.0),
                )
            }
        };
        let to_hash = // P(leftH)
            left_hash.elements.into_iter()
                // P(rightH)
                .chain(right_hash.elements)
                // P(min)
                .chain(self.min.to_fields())
                // P(max)
                .chain(self.max.to_fields())
                // P(id)
                .chain(std::iter::once(F::from_canonical_u64(self.secondary_index_column)))
                // P(value)
                .chain(self.secondary_index_value().to_fields())
                // P(cell_tree_hash)
                .chain(HashOut::from_bytes(
                    &self.cell_root_hash.as_ref().map(|h| h.0)
                        .unwrap_or(empty_poseidon_hash().to_bytes().try_into().unwrap())
                ).to_fields())
                .collect::<Vec<_>>();
        tracing::trace!(
            "\nRYHOPE aggregate() Row: id {:?}, value {:?} (empty hash{}) left_hash {:?}, right_hash {:?} min {:?}, max {:?}, tree_root_hash {:?}",
            self.secondary_index_column,
            self.secondary_index_value(),
            left_hash == *empty_poseidon_hash(),
            hex::encode(left_hash.to_bytes()),
            hex::encode(right_hash.to_bytes()),
            self.min,
            self.max,
            hex::encode(self.cell_root_hash.as_ref().map(|h| h.0)
                .unwrap_or(empty_poseidon_hash().to_bytes().try_into().unwrap())),
        );
        self.hash = HashOutput(H::hash_no_pad(&to_hash).to_bytes().try_into().unwrap());
    }
}

impl ToNonce for usize {
    fn to_nonce(&self) -> RowTreeKeyNonce {
        self.to_be_bytes().to_vec()
    }
}

impl ToNonce for Vec<u8> {
    fn to_nonce(&self) -> RowTreeKeyNonce {
        self.to_owned()
    }
}

impl ToNonce for U256 {
    fn to_nonce(&self) -> RowTreeKeyNonce {
        // we don't need to keep all the bytes, only the ones that matter.
        // Since we are storing this inside psql, any storage saving is good to take !
        self.to_be_bytes_trimmed_vec()
    }
}

impl<PrimaryIndex> ToFromBytea for RowPayload<PrimaryIndex>
where
    PrimaryIndex: std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Clone
        + Sized
        + Serialize
        + for<'a> Deserialize<'a>,
{
    fn to_bytea(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }

    fn from_bytea(bytes: Vec<u8>) -> Self {
        serde_json::from_slice(&bytes).expect("invalid row payload JSON in database")
    }
}

impl ToFromBytea for RowTreeKey {
    fn to_bytea(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("unable to serialize row key to json")
    }

    fn from_bytea(bytes: Vec<u8>) -> Self {
        serde_json::from_slice(&bytes).expect("invalid row key JSON in db")
    }
}
