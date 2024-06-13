use crate::types::{HashCat, HashPair, Hex, MerkError, SharedHashPair};
use std::collections::HashMap;

const MAX_DEPTH: usize = 30;
const ROOT_INDEX: usize = 0;

#[derive(Debug)]
pub struct MerkleTree {
    depth: usize,
    size: usize,
    leaf_start_index: usize,
    store: HashMap<usize, SharedHashPair>, // map tree index item to shared hash pair
    master: HashMap<String, SharedHashPair>, // store a single master copy of Rc value
}

impl MerkleTree {
    pub fn new(depth: usize, initial_value: &str) -> Self {
        if depth == 0 || depth > MAX_DEPTH {
            panic!("Specified depth must be greater than 0 and less than 30");
        }

        let size = Self::size(depth);
        let store = HashMap::with_capacity(size); // maps tree index out to original rc values store in master
        let master = HashMap::with_capacity(depth); // shared out rc originals

        let mut tree = Self {
            depth,
            size,
            leaf_start_index: Self::size(depth-1),
            store,
            master,
        };

        tree.initialize(initial_value)
            .expect("Unable to create tree");

        tree
    }

    pub fn root(&self) -> String {
        self.store
            .get(&0)
            .map_or(String::new(), |v| v.borrow().hash_key.clone())
    }

    pub fn num_leaves(&self) -> usize {
        self.size - self.leaf_start_index
    }

    pub(crate) fn size(depth: usize) -> usize {
        usize::pow(2, depth as u32) - 1
    }

    /******************* Index API functions ********************/

    pub(crate) fn index(&self, depth: usize, offset: usize) -> usize {
        let index = usize::pow(2, depth as u32) - 1 + offset; // (2,0) => 2^depth -1 + offset => 2^2 - 1 + 0 => 3 index

        if index >= self.size {
            eprintln!("Index is too large, and does not exist in tree");
            return ROOT_INDEX;
        }

        index
    }

    pub(crate) fn parent_index(&self, index: usize) -> usize {
        if index == 0 || index >= self.size {
            return ROOT_INDEX;
        }

        match index % 2 {
            0 => (index - 2) / 2,
            1 => (index - 1) / 2,
            _ => unreachable!(),
        }
    }

    pub(crate)  fn left_child_index(&self, index: usize) -> usize {
        let child_index = 2 * index + 1;
        if child_index >= self.size {
            eprintln!("Child index is too large, and does not exist in tree");
            return ROOT_INDEX;
        }
        child_index
    }

    pub(crate) fn right_child_index(&self, index: usize) -> usize {
        let child_index = 2 * index + 2;

        if child_index >= self.size {
            eprintln!("Child index is too large, and does not exist in tree");
            return ROOT_INDEX;
        }
        child_index
    }

    pub fn set_with_scale(&mut self, leaf_index: usize, scale: usize, value: &str) {
        if value.len() % 2 == 1 {
            eprintln!("unable to set as value is malformed as len is of odd length");
            return
        }

        if !self.valid_leaf_index(leaf_index) { return }

        let v = Hex::trim_prefix(value);
        let value = if scale == 1 { v.to_string() } else { Hex::scale(scale, v) };

        self.set(leaf_index + self.leaf_start_index, value)
    }

    /******************* Private helper functions  ********************/

    fn initialize(&mut self, value: &str) -> Result<(), MerkError> {
        let mut acc_hash_str = Hex::trim_prefix(value).to_string();
        let mut acc_bytes: Vec<u8> =
            Hex::decode(&acc_hash_str).inspect_err(|e| eprintln!("{}", &e))?;

        let mut r = self.size;

        // Traverse levels of merkle tree starting with last level (leaves first)
        // Until reach root node - root level

        for d in (0..self.depth).rev() {
            let shared_hash = HashPair::new_shared(acc_hash_str.clone(), acc_bytes);

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


    // recursive set function that sets specified tree node index with appropriate
    // hash string value
    fn set(&mut self, index: usize, value: String) {
        use std::rc::Rc;

        let new_hash = HashPair::new_shared_key(value).unwrap(); // value already been validated

        // Prune shared hashmap for bloat if a shared_hash is no longer being referenced

        if let Some(shared_hash) = self.store.get(&index) {

            // if this is the last reference to this shared hash other than
            // the original, remove it from the store, and remove it from shared

            if Rc::strong_count(&shared_hash) == 2 {
                let str_key = &shared_hash.borrow().hash_key.clone();

                self.store.remove(&index); // strong count should be 1 after
                self.master.remove(str_key);
            }
        }

        // Note: don't store it into master
        // Put in store only, as this is a one-off
        self.store.insert(index, new_hash.clone());

        let p_index = self.parent_index(index);

        if index == p_index { return } // reached the top, nothing further to do, abort from recursion

        // odd index is left child, even is right child
        let sibling_index = if index % 2 == 0 { index - 1 } else { index + 1 };
        let sibling_hash = self.store.get(&sibling_index).unwrap();

        // compute new parent hash based on new hash and existing sibling hash
        let p_hash = HashCat::concat(&new_hash.borrow().bytes, &sibling_hash.borrow().bytes);
        self.set(p_index, Hex::encode(&p_hash))
    }

    fn valid_leaf_index(&self, leaf_index: usize) -> bool {
        if leaf_index + self.leaf_start_index < self.size {
            true
        }
        else {
            eprintln!("leaf index is not valid");
            false
        }
    }

    /******************* Test-only API ********************/

    #[cfg(test)]
    pub(crate) fn contains_key(&self, key: &str) -> bool {
        self.master.contains_key(key)
    }

    #[cfg(test)]
    pub(crate) fn contains_key_at(&self, index: usize, key: &str) -> bool {
        if let Some(shared_item) = self.store.get(&index) {
            shared_item.borrow().hash_key == key
        } else {
            false
        }
    }

    #[cfg(test)]
    pub(crate) fn master_size(&self) -> usize { self.master.len() }

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
    // Check tree creation with invalid parameters that are ultimately "unrecoverable"
    pub fn tree_create_test1() {
        // suppress panic output
        std::panic::set_hook(Box::new(|_| {})); 

        // catch unrecoverable panic
        let panic1 = std::panic::catch_unwind(|| {
           MerkleTree::new(5, "abcde");
        });

        assert!(&panic1.is_err());

        // catch unrecoverable panic
        let panic2 = std::panic::catch_unwind(|| {
            MerkleTree::new(50, "abcdef");
        });

        assert!(&panic2.is_err());

        // catch unrecoverable panic
        let panic3 = std::panic::catch_unwind(|| {
            MerkleTree::new(0, "abcdef");
        });

        assert!(&panic3.is_err());
    }

    #[test]
    // Check large tree creation
    pub fn tree_create_test2() {
        let tree;

        tree = MerkleTree::new(
            20,
            "0xabababababababababababababababababababababababababababababababab",
        );

        assert_eq!(
            tree.root(),
            "d4490f4d374ca8a44685fe9471c5b8dbe58cdffd13d30d9aba15dd29efb92930"
        );
    }

    #[test]
    // Check tree creation and verify node hashes
    pub fn tree_create_test3() {
        let mut tree;

        // construct tree of depths 1 and 2, and size 1 and 3
        tree = MerkleTree::new(1, "0xab");
        assert_eq!(tree.root(), "ab"); // single node so no hash concats!

        tree = MerkleTree::new(2, "0xab"); // depth of 2 size 3

        assert_eq!(tree.root(), "5fdf86416e09b2b1c0b91afe771d4e6ada2b0daed0066f8aed911109e33f3e34");

        // check level hashes for a tree of depth 3

        tree = MerkleTree::new(3, "0xabababababababababababababababababababababababababababababababab");

        let level_hash_str = [
            "abababababababababababababababababababababababababababababababab", // 0 - leaf
            "699fc94ff1ec83f1abf531030e324003e7758298281645245f7c698425a5e0e7", // 1 - inner
            "a2422433244a1da24b3c4db126dcc593666f98365403e6aaf07fae011c824f09"  // 2 - root
        ];

        // ensure our computed hashes at various node levels are found within tree
        for i in 0..level_hash_str.len() {
            assert!(tree.contains_key(level_hash_str[i]));
        }

        // ensure our computed hashes are correct for each tree level, from leaves, inner to root
        for i in 3..7 {
            assert!(tree.contains_key_at(i, level_hash_str[0]));
        }

        for i in 1..3 {
            assert!(tree.contains_key_at(i, level_hash_str[1]));
        }

        assert!(tree.contains_key_at(0, level_hash_str[2])); // verify root value
        assert_eq!(tree.root(), level_hash_str[2]); // same
    }


    #[test]
    pub fn test_tree_set() {
        let mut tree;

        tree = tree_set_with_scale(2);
        assert_eq!(tree.root(), "aa679f6812decf546048d3d610fe9b3567d8c4b6d2e4013360180617c10acccc");

        tree = tree_set_with_scale(5);
        assert_eq!(tree.root(), "8ecaaf19d68ed7d67ae175628dd6f1e73ae7a8b35d7ed394dfb8f54a7feadc0f");
    }

    // helper function to create and modify tree with set with scale function
    pub fn tree_set_with_scale(depth: usize) -> MerkleTree {
        let mut tree = MerkleTree::new(depth, "0x0000000000000000000000000000000000000000000000000000000000000000");

        // the master size should be the depth of the tree because that's the number of unique values
        // essentially 1 unique value per level
        assert_eq!(tree.master_size(), depth);

        for i in 0..tree.num_leaves() {
            tree.set_with_scale(i, i, "1111111111111111111111111111111111111111111111111111111111111111");
        }

        // since all the leaves have changed, the intermediate node values change as a result
        // this percolates up to the root
        // the previous master values that were resident in the tree should be overwritten with new percolated values
        // hence the master values table should be empty

        assert_eq!(tree.master_size(), 0);

        tree
    }
}
