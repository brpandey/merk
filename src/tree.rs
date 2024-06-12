use crate::types::{HashCat, HashPair, Hex, MerkError, SharedHashPair};
use std::collections::HashMap;

const MAX_DEPTH: usize = 30;
const ROOT_INDEX: usize = 0;

#[derive(Debug)]
pub struct MerkleTree {
    depth: usize,
    size: usize,
    store: HashMap<usize, SharedHashPair>, // map tree index item to shared hash pair
    master: HashMap<String, SharedHashPair>, // store a single master copy of Rc value
}

impl MerkleTree {
    pub fn new(depth: usize, initial_value: &str) -> Self {
        if depth > MAX_DEPTH {
            panic!("Specified depth must be less than 30");
        }

        let tree_size = |depth: usize| usize::pow(2, depth as u32) - 1;
        let size = tree_size(depth);

        let store = HashMap::with_capacity(size); // maps tree index out to original rc values store in master
        let master = HashMap::with_capacity(depth); // shared out rc originals

        let mut tree = Self {
            depth,
            size,
            store,
            master,
        };

        tree.initialize(initial_value)
            .expect("Unable to create tree");
        //        if tree.initialize(initial_value).is_err() { return Default::default()};

        tree
    }

    pub fn root(&self) -> String {
        self.store
            .get(&0)
            .map_or(String::new(), |v| v.borrow().hash_key.clone())
    }

    /******************* Index API functions ********************/

    pub fn index(&self, depth: usize, offset: usize) -> usize {
        let index = usize::pow(2, depth as u32) - 1 + offset; // (2,0) => 2^depth -1 + offset => 2^2 - 1 + 0 => 3 index

        if index >= self.size {
            eprintln!("Index is too large, and does not exist in tree");
            return ROOT_INDEX;
        }

        index
    }

    pub fn parent_index(&self, index: usize) -> usize {
        if index == 0 || index >= self.size {
            return ROOT_INDEX;
        }

        match index % 2 {
            0 => (index - 2) / 2,
            1 => (index - 1) / 2,
            _ => unreachable!(),
        }
    }

    pub fn left_child_index(&self, index: usize) -> usize {
        let child_index = 2 * index + 1;
        if child_index >= self.size {
            eprintln!("Child index is too large, and does not exist in tree");
            return ROOT_INDEX;
        }
        child_index
    }

    pub fn right_child_index(&self, index: usize) -> usize {
        let child_index = 2 * index + 2;

        if child_index >= self.size {
            eprintln!("Child index is too large, and does not exist in tree");
            return ROOT_INDEX;
        }
        child_index
    }

    fn initialize(&mut self, value: &str) -> Result<(), MerkError> {
        let mut acc_hash_str = Hex::trim_prefix(value).to_string();
        let mut acc_bytes: Vec<u8> =
            Hex::decode(&acc_hash_str).inspect_err(|e| eprintln!("{}", &e))?;

        let mut r = self.size;

        // Traverse levels of merkle tree starting with last level (leaves first)
        // Until reach root node - root level

        for d in (0..self.depth).rev() {
            let shared_hash = HashPair::new_shared_(acc_hash_str.clone(), acc_bytes);

            self.master.insert(acc_hash_str, shared_hash.clone()); // store local variable into master store

            let l = usize::pow(2, d as u32) - 1;

            for index in l..r {
                self.store.insert(index, shared_hash.clone()); // stash into mapping
            }

            r = l;

            acc_bytes = HashCat::concat(&shared_hash.borrow().bytes, &shared_hash.borrow().bytes); // O(depth) invocations of Sha3
            acc_hash_str = Hex::encode(&acc_bytes);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn parent_test() {
        let tree: MerkleTree = MerkleTree::new(5, "abcdef");

        assert_eq!(0, tree.parent_index(0));
        assert_eq!(0, tree.parent_index(345));

        assert_eq!(0, tree.parent_index(1));

        assert_eq!(1, tree.parent_index(3));
        assert_eq!(2, tree.parent_index(6));

        // given a tree of depth 4 the leaves are 7..14, the grandparents
        // are either 1 or 2, with parents being either 3, 4 and 5, 6
        for i in 7..10 {
            assert_eq!(1, tree.parent_index(tree.parent_index(i)));
        }

        for i in 11..14 {
            assert_eq!(2, tree.parent_index(tree.parent_index(i)));
        }
    }

    #[test]
    pub fn tree_create_test() {
        //        let mut tree = MerkleTree::new(5, "abcde");

        //        let mut tree = MerkleTree::new(50, "abcdef");

        let tree = MerkleTree::new(
            20,
            "0xabababababababababababababababababababababababababababababababab",
        );

        assert_eq!(
            tree.root(),
            "d4490f4d374ca8a44685fe9471c5b8dbe58cdffd13d30d9aba15dd29efb92930"
        );
    }
}
