/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    define_HashmapE, error, fail, AccountStorage, BuilderData, Cell, Deserializable, HashmapType,
    IBitstring, Result, Serializable, SliceData, StateInit, StorageUsed, UInt256,
};
use std::{collections::BTreeMap, ops::Not};

#[cfg(test)]
#[path = "tests/test_storage_stat.rs"]
mod tests;

const DICT_PROOF_TAG: u32 = 0x37c1e3fc;
const CONSENSUS_EXTRA_DATA_TAG: u32 = 0x638eb292;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct StorageStatCellInfo {
    pub ref_count: u32,
    pub max_merkle_depth: u8,
    // not serialized
    pub ref_count_diff: i32,
}

impl Serializable for StorageStatCellInfo {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        cell.append_u32(self.ref_count)?;
        cell.append_bits(self.max_merkle_depth as usize, 2)?;
        Ok(())
    }
}
impl Deserializable for StorageStatCellInfo {
    fn read_from(&mut self, cell: &mut SliceData) -> Result<()> {
        self.ref_count = cell.get_next_u32()?;
        self.max_merkle_depth = cell.get_next_int(2)? as u8;
        self.ref_count_diff = 0;
        Ok(())
    }
}

define_HashmapE!(StorageStatDict, 256, StorageStatCellInfo);

#[derive(Default, Clone, PartialEq)]
pub struct AccountStorageStat {
    dict: StorageStatDict,
    roots: Vec<Cell>,
    total_cells: u64,
    total_bits: u64,
    cache: BTreeMap<UInt256, StorageStatCellInfo>,
    dict_updated: bool,
}

impl std::fmt::Debug for AccountStorageStat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut builder = f.debug_struct("AccountStorageStat");
        builder.field("dict", &self.dict);
        builder.field("total_cells", &self.total_cells);
        builder.field("total_bits", &self.total_bits);
        builder.field("dict_updated", &self.dict_updated);
        builder.finish()
    }
}

impl AccountStorageStat {
    pub fn new() -> Self {
        Self {
            dict: StorageStatDict::new(),
            roots: Vec::new(),
            total_cells: 0,
            total_bits: 0,
            cache: Default::default(),
            dict_updated: true,
        }
    }

    pub fn try_from_dict(dict: Cell, storage: &AccountStorage, used: &StorageUsed) -> Result<Self> {
        let storage_cell = storage.write_to_new_cell()?;
        let total_bits = used.bits().checked_sub(storage_cell.length_in_bits() as u64);
        let total_cells = used.cells().checked_sub(1);
        let (Some(total_cells), Some(total_bits)) = (total_cells, total_bits) else {
            fail!(
                "StorageUsed is too small (cells {}, bits {}, storage root bits {}), \
                cannot create AccountStorageStat",
                used.cells(),
                used.bits(),
                storage_cell.length_in_bits()
            )
        };
        Ok(Self {
            dict: StorageStatDict::with_hashmap(Some(dict)),
            roots: Self::get_roots(storage.state_init()),
            total_cells,
            total_bits,
            cache: Default::default(),
            dict_updated: false,
        })
    }

    pub fn dict_root(&mut self) -> Result<Option<&Cell>> {
        if !self.dict_updated {
            let values = self.cache.iter_mut().filter(|(_, data)| data.ref_count_diff != 0).map(
                |(hash, data)| {
                    data.ref_count_diff = 0;
                    if data.ref_count == 0 {
                        (SliceData::from(hash), None)
                    } else {
                        (SliceData::from(hash), data.write_to_bitstring().ok())
                    }
                },
            );

            #[cfg(not(target_family = "wasm"))]
            let now = std::time::Instant::now();
            self.dict.0.hashmap_multiset(values)?;
            #[cfg(not(target_family = "wasm"))]
            log::debug!("TIME Storage stat dict update {:?}", now.elapsed());

            self.dict_updated = true;
        }

        Ok(self.dict.root())
    }

    pub fn update(&mut self, storage: &AccountStorage) -> Result<StorageUsed> {
        self.update_for_transaction(storage, true)
    }

    /// Reconcile the actual graph cache without deciding advertised metadata.
    /// Native v10+ excludes extra currencies from storage accounting.
    pub(crate) fn update_for_transaction(
        &mut self,
        storage: &AccountStorage,
        exclude_extra_currencies: bool,
    ) -> Result<StorageUsed> {
        #[cfg(not(target_family = "wasm"))]
        let now = std::time::Instant::now();
        let roots = if exclude_extra_currencies {
            Self::get_roots(storage.state_init())
        } else {
            let cell = storage.serialize()?;
            (0..cell.references_count())
                .map(|index| cell.reference(index))
                .collect::<Result<_>>()?
        };
        self.replace_roots(roots)?;
        #[cfg(not(target_family = "wasm"))]
        log::debug!("TIME Storage stat replace roots {:?}", now.elapsed());
        let cell = storage.serialize()?;
        let cells =
            self.total_cells.checked_add(1).ok_or_else(|| error!("storage cell count overflow"))?;
        let bits = self
            .total_bits
            .checked_add(cell.bit_length() as u64)
            .ok_or_else(|| error!("storage bit count overflow"))?;
        StorageUsed::with_values_checked(cells, bits)
    }

    pub fn get_roots(storage: Option<&StateInit>) -> Vec<Cell> {
        match storage {
            Some(state_init) => {
                // storage root and currency collection are not counted in stats
                let mut roots = Vec::with_capacity(3);
                if let Some(code) = state_init.code() {
                    roots.push(code.clone());
                }
                if let Some(data) = state_init.data() {
                    roots.push(data.clone());
                }
                if let Some(lib) = state_init.library.root() {
                    roots.push(lib.clone());
                }
                roots
            }
            None => Vec::new(),
        }
    }

    fn replace_roots(&mut self, mut roots: Vec<Cell>) -> Result<()> {
        // Match native: roots are a multiset. contains() loses changes in
        // multiplicity when code/data/library share the same root.
        if roots.is_empty() {
            *self = Self::new();
            return Ok(());
        }
        roots.sort_by_key(Cell::repr_hash);
        self.roots.sort_by_key(Cell::repr_hash);
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let (mut new_index, mut old_index) = (0, 0);
        while new_index < roots.len() || old_index < self.roots.len() {
            match (roots.get(new_index), self.roots.get(old_index)) {
                (Some(new), Some(old)) => match new.repr_hash().cmp(&old.repr_hash()) {
                    std::cmp::Ordering::Equal => {
                        new_index += 1;
                        old_index += 1;
                    }
                    std::cmp::Ordering::Less => {
                        added.push(new.clone());
                        new_index += 1;
                    }
                    std::cmp::Ordering::Greater => {
                        removed.push(old.clone());
                        old_index += 1;
                    }
                },
                (Some(new), None) => {
                    added.push(new.clone());
                    new_index += 1;
                }
                (None, Some(old)) => {
                    removed.push(old.clone());
                    old_index += 1;
                }
                (None, None) => break,
            }
        }
        if added.is_empty() && removed.is_empty() {
            return Ok(());
        }
        self.dict_updated = false;
        // Add first so shared subgraphs remain live while old roots disappear.
        for root in added {
            self.add_cell(&root)?;
        }
        for root in removed {
            self.remove_cell(&root)?;
        }
        self.roots = roots;
        Ok(())
    }

    fn add_cell(&mut self, cell: &Cell) -> Result<u8> {
        let hash = cell.repr_hash();
        let mut max_merkle_depth = 0;
        if let Some(data) = self.cache.get_mut(&hash) {
            data.ref_count += 1;
            data.ref_count_diff += 1;
            max_merkle_depth = data.max_merkle_depth;

            if data.ref_count == 1 {
                for i in 0..cell.references_count() {
                    self.add_cell(&cell.reference_without_usage(i)?)?;
                }
                self.total_cells += 1;
                self.total_bits += cell.bit_length() as u64;
            }
        } else if let Some(Ok(Some(data))) =
            self.dict.is_empty().not().then(|| self.dict.get(&hash))
        {
            max_merkle_depth = data.max_merkle_depth;
            self.cache.insert(
                hash,
                StorageStatCellInfo {
                    ref_count: data.ref_count + 1,
                    max_merkle_depth,
                    ref_count_diff: 1,
                },
            );
        } else {
            for i in 0..cell.references_count() {
                let child_depth = self.add_cell(&cell.reference_without_usage(i)?)?;
                max_merkle_depth = max_merkle_depth.max(child_depth);
            }
            if cell.is_merkle() {
                max_merkle_depth += 1;
            }
            self.total_cells += 1;
            self.total_bits += cell.bit_length() as u64;
            let data = StorageStatCellInfo { ref_count: 1, max_merkle_depth, ref_count_diff: 1 };
            self.cache.insert(hash, data);
        }
        Ok(max_merkle_depth)
    }

    fn remove_cell(&mut self, cell: &Cell) -> Result<()> {
        let hash = cell.repr_hash();
        let removed = if let Some(data) = self.cache.get_mut(&hash) {
            data.ref_count -= 1;
            data.ref_count_diff -= 1;
            data.ref_count == 0
        } else {
            let data = self.dict.get(&hash)?.ok_or_else(|| {
                error!("Cell with hash {} not found in storage stat dictionary", hash)
            })?;
            self.cache.insert(
                hash,
                StorageStatCellInfo {
                    ref_count: data.ref_count - 1,
                    max_merkle_depth: data.max_merkle_depth,
                    ref_count_diff: -1,
                },
            );
            data.ref_count == 1
        };

        if removed {
            for i in 0..cell.references_count() {
                self.remove_cell(&cell.reference_without_usage(i)?)?;
            }
            self.total_cells -= 1;
            self.total_bits -= cell.bit_length() as u64;
        }

        Ok(())
    }

    pub fn total_cells(&self) -> u64 {
        self.total_cells
    }

    pub fn total_bits(&self) -> u64 {
        self.total_bits
    }

    pub fn max_merkle_depth(&self) -> Result<u8> {
        let mut result = 0;
        for root in &self.roots {
            let depth = if let Some(data) = self.cache.get(&root.repr_hash()) {
                data.max_merkle_depth
            } else {
                self.dict
                    .get(&root.repr_hash())?
                    .ok_or_else(|| {
                        error!("Root {} not found in storage stat dictionary", root.repr_hash())
                    })?
                    .max_merkle_depth
            };
            result = result.max(depth);
        }
        Ok(result)
    }
}

#[derive(Debug, Default, Clone)]
pub struct AccountStorageDictProof {
    pub proof: Cell,
}

impl Serializable for AccountStorageDictProof {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        cell.append_u32(DICT_PROOF_TAG)?;
        cell.checked_append_reference(self.proof.clone())?;
        Ok(())
    }
}

impl Deserializable for AccountStorageDictProof {
    fn read_from(&mut self, cell: &mut SliceData) -> Result<()> {
        let tag = cell.get_next_u32()?;
        if tag != DICT_PROOF_TAG {
            fail!(
                "Invalid AccountStorageDictProof tag: expected {:#x}, found {:#x}",
                DICT_PROOF_TAG,
                tag
            );
        }
        self.proof = cell.checked_drain_reference()?;
        Ok(())
    }
}

/// consensus_extra_data#638eb292 flags:# gen_utime_ms:uint64 = ConsensusExtraData;
#[derive(Debug, Default, Clone)]
pub struct ConsensusExtraData {
    pub flags: u32,
    pub gen_utime_ms: u64,
}

impl ConsensusExtraData {
    pub const TAG: u32 = CONSENSUS_EXTRA_DATA_TAG;
}

impl Serializable for ConsensusExtraData {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        cell.append_u32(CONSENSUS_EXTRA_DATA_TAG)?;
        cell.append_u32(self.flags)?;
        cell.append_u64(self.gen_utime_ms)?;
        Ok(())
    }
}

impl Deserializable for ConsensusExtraData {
    fn read_from(&mut self, cell: &mut SliceData) -> Result<()> {
        let tag = cell.get_next_u32()?;
        if tag != CONSENSUS_EXTRA_DATA_TAG {
            fail!(
                "Invalid ConsensusExtraData tag: expected {:#x}, found {:#x}",
                CONSENSUS_EXTRA_DATA_TAG,
                tag
            );
        }
        self.flags = cell.get_next_u32()?;
        self.gen_utime_ms = cell.get_next_u64()?;
        Ok(())
    }
}
