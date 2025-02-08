use alloy::primitives::Address;
use std::collections::{HashMap, HashSet};
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Add,
    Replace,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacetInfo {
    action: Action,
    is_freezable: bool,
    selectors: HashSet<[u8; 4]>,
}

#[derive(Debug, Clone, Eq)]
pub struct FacetCutSet {
    facets: HashMap<Address, FacetInfo>,
}

impl PartialEq for FacetCutSet {
    fn eq(&self, other: &Self) -> bool {
        self.facets == other.facets
    }
}

impl FacetCutSet {
    pub fn new() -> Self {
        Self {
            facets: HashMap::new(),
        }
    }

    pub fn add_facet(&mut self, address: Address, is_freezable: bool, action: Action) {
        self.facets.insert(
            address,
            FacetInfo {
                action,
                is_freezable,
                selectors: HashSet::new(),
            },
        );
    }

    pub fn add_selector(&mut self, address: Address, selector: [u8; 4]) {
        if let Some(facet) = self.facets.get_mut(&address) {
            facet.selectors.insert(selector);
        } else {
            panic!("Facet at address {:?} not found", address);
        }
    }

    pub fn merge(mut self, another_set: FacetCutSet) -> Self {
        for (address, new_facet) in another_set.facets {
            if let Some(existing_facet) = self.facets.get(&address) {
                if existing_facet.action != new_facet.action || existing_facet.is_freezable != new_facet.is_freezable {
                    panic!(
                        "Conflict while merging: address {:?} has different action or freezability",
                        address
                    );
                }
                let mut merged_facet = existing_facet.clone();
                merged_facet.selectors.extend(new_facet.selectors);
                self.facets.insert(address, merged_facet);
            } else {
                self.facets.insert(address, new_facet);
            }
        }

        self
    }
}

impl PartialOrd for FacetCutSet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.facets.len().cmp(&other.facets.len()))
    }
}

impl Ord for FacetCutSet {
    fn cmp(&self, other: &Self) -> Ordering {
        self.facets.len().cmp(&other.facets.len())
    }
}
