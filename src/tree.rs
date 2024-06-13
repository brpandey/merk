use either::*;
use std::collections::HashMap;

use crate::types::{HashCat, HashPair, Hex, MerkError, SharedHashPair};

const MAX_DEPTH: usize = 30;
const ROOT_INDEX: usize = 0;

pub type MerkleProof = Vec<Either<String, String>>;

#[derive(Debug)]
pub struct MerkleTree {
    depth: usize,
    size: usize,
    leaf_start_index: usize,
    // store comprises the tree data structure, it maps the node index to the shared hash pair
    store: HashMap<usize, SharedHashPair>,
    // store a single master copy of shared Rc values
    master: HashMap<String, SharedHashPair>, 
}

impl MerkleTree {
    pub fn new(depth: usize, initial_value: &str) -> Self {
        if depth == 0 || depth > MAX_DEPTH {
            panic!("Specified depth must be greater than 0 and less than 30");
        }

        let size = Self::size(depth);
        let store = HashMap::with_capacity(size); // Maps tree index out to original rc values store in master
        let master = HashMap::with_capacity(depth); // Shared out rc originals

        let mut tree = Self {
            depth,
            size,
            leaf_start_index: Self::size(depth - 1),
            store,
            master,
        };

        tree.initialize(initial_value)
            .expect("Unable to create tree"); // 

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

    pub fn set_with_scale(&mut self, leaf_index: usize, scale: usize, value: &str) {
        if value.len() % 2 == 1 {
            eprintln!("unable to set as value is malformed as len is of odd length");
            return;
        }

        if !self.valid_leaf_index(leaf_index) {
            return;
        }

        let v = Hex::trim_prefix(value);
        let value = if scale == 1 {
            v.to_string()
        } else {
            Hex::scale(scale, v)
        };

        self.set(leaf_index + self.leaf_start_index, value)
    }

    pub fn proof(&self, leaf_index: usize) -> Vec<Either<String, String>> {
        let mut acc = vec![];

        if !self.valid_leaf_index(leaf_index) {
            return acc;
        }

        let mut index = leaf_index + self.leaf_start_index;

        while index != ROOT_INDEX {
            // odd index is left child, even is right child
            let sibling_index = if index % 2 == 0 {
                Left(index - 1) // sibling audit hash is on left
            } else {
                Right(index + 1) // sibling audit hash is on right
            };

            let path_hash_item = sibling_index.map(|idx| {
                let sibling_hash = self.store.get(&idx).unwrap();
                sibling_hash.borrow().hash_key.clone()
            });

            acc.push(path_hash_item);

            index = self.parent_index(index);
        }

        acc
    }

    pub fn verify(&self, proof: MerkleProof, leaf_value: &str) -> Result<String, MerkError> {
        let mut acc_bytes: Vec<u8> = Hex::decode(leaf_value)?;

        for path_item in proof.iter() {
            acc_bytes = match path_item {
                Left(item) => HashCat::concat_l(item, &acc_bytes)?, // sibling audit hash goes on left, computed value on right
                Right(item) => HashCat::concat_r(&acc_bytes, item)?, // sibling audit hash goes on right, computed value on left
            };
        }

        let root = Hex::encode(acc_bytes);

        Ok(root)
    }

    /******************* Index API functions ********************/

    pub(crate) fn index(&self, depth: usize, offset: usize) -> usize {
        // (2,0) => 2^depth -1 + offset => 2^2 - 1 + 0 => 3 index
        let index = usize::pow(2, depth as u32) - 1 + offset; 

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

    pub(crate) fn left_child_index(&self, index: usize) -> usize {
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

            // master provides a central place to see the ref counts for the hashpairs being shared out
            self.master.insert(acc_hash_str, shared_hash.clone());

            let l = usize::pow(2, d as u32) - 1;

            for index in l..r {
                // populate the tree
                self.store.insert(index, shared_hash.clone());
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
        // While replacing hash value, check if old value is no longer
        // being referenced from bulk initialization
        self.prune(index);

        // Create new shared key
        // Put in store only (not master), as this is a one-off

        // TODO: value doesn't need to be wrapped in RC,
        // Store should take either SharedHashPair or HashPair
        let new_hash = HashPair::new_shared_key(value).unwrap();
        self.store.insert(index, new_hash.clone());

        let p_index = self.parent_index(index);

        if index == p_index {
            return;
        } // reached the top, nothing further to do, abort from recursion

        let l_index = self.left_child_index(p_index);
        let r_index = self.right_child_index(p_index);

        let l_hash = self.store.get(&l_index).unwrap();
        let r_hash = self.store.get(&r_index).unwrap();

        // compute new parent hash
        let p_hash = HashCat::concat(&l_hash.borrow().bytes, &r_hash.borrow().bytes);
        self.set(p_index, Hex::encode(p_hash))
    }

    fn prune(&mut self, index: usize) {
        use std::rc::Rc;

        // Prune master hashmap for bloat only if shared_hash is no longer being referenced
        if let Some(shared_hash) = self.store.get(&index) {
            // if this is the last reference to this shared hash other than
            // the original, remove it from the store, and remove it from shared
            if Rc::strong_count(shared_hash) == 2 {
                let str_key = &shared_hash.borrow().hash_key.clone();

                self.store.remove(&index); // strong count should be 1 after remove
                self.master.remove(str_key);
            }
        }
    }

    fn valid_leaf_index(&self, leaf_index: usize) -> bool {
        if leaf_index + self.leaf_start_index < self.size {
            true
        } else {
            eprintln!("leaf index is not valid");
            false
        }
    }

    fn size(depth: usize) -> usize {
        usize::pow(2, depth as u32) - 1
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
    pub(crate) fn key_at(&self, index: usize) -> String {
        if let Some(shared_item) = self.store.get(&index) {
            shared_item.borrow().hash_key.clone()
        } else {
            String::new()
        }
    }

    #[cfg(test)]
    pub(crate) fn master_size(&self) -> usize {
        self.master.len()
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

        assert_eq!(
            tree.root(),
            "5fdf86416e09b2b1c0b91afe771d4e6ada2b0daed0066f8aed911109e33f3e34"
        );

        // check level hashes for a tree of depth 3

        tree = MerkleTree::new(
            3,
            "0xabababababababababababababababababababababababababababababababab",
        );

        let level_hash_str = [
            "abababababababababababababababababababababababababababababababab", // 0 - leaf
            "699fc94ff1ec83f1abf531030e324003e7758298281645245f7c698425a5e0e7", // 1 - inner
            "a2422433244a1da24b3c4db126dcc593666f98365403e6aaf07fae011c824f09", // 2 - root
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
        assert_eq!(
            tree.root(),
            "35e794f1b42c224a8e390ce37e141a8d74aa53e151c1d1b9a03f88c65adb9e10"
        );

        tree = tree_set_with_scale(5);
        assert_eq!(
            tree.root(),
            "57054e43fa56333fd51343b09460d48b9204999c376624f52480c5593b91eff4"
        );

        assert_eq!(
            tree.key_at(17),
            "2222222222222222222222222222222222222222222222222222222222222222"
        );
        assert_eq!(
            tree.key_at(7),
            "35e794f1b42c224a8e390ce37e141a8d74aa53e151c1d1b9a03f88c65adb9e10"
        );
        assert_eq!(
            tree.key_at(4),
            "26fca7737f48fa702664c8b468e34c858e62f51762386bd0bddaa7050e0dd7c0"
        );
        assert_eq!(
            tree.key_at(2),
            "e7e11a86a0c1d8d8624b1629cb58e39bb4d0364cb8cb33c4029662ab30336858"
        );
    }

    // helper function to create and modify tree with set with scale function
    pub fn tree_set_with_scale(depth: usize) -> MerkleTree {
        let mut tree = MerkleTree::new(
            depth,
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        );

        // the master size should be the depth of the tree because that's the number of unique values
        // essentially 1 unique value per level
        assert_eq!(tree.master_size(), depth);

        for i in 0..tree.num_leaves() {
            tree.set_with_scale(
                i,
                i,
                "1111111111111111111111111111111111111111111111111111111111111111",
            );
        }

        // since all the leaves have changed, the intermediate node values change as a result
        // this percolates up to the root
        // the previous master values that were resident in the tree should be overwritten with new percolated values
        // hence the master values table should be empty

        assert_eq!(tree.master_size(), 0);

        tree
    }

    #[test]
    pub fn tree_proof_verify() {
        let mut tree = MerkleTree::new(
            5,
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        );

        assert_eq!(tree.num_leaves(), 16);

        tree = tree_set_with_scale(5);

        assert_eq!(
            tree.root(),
            "57054e43fa56333fd51343b09460d48b9204999c376624f52480c5593b91eff4"
        );

        let proof = vec![
            Left("2222222222222222222222222222222222222222222222222222222222222222"),
            Left("35e794f1b42c224a8e390ce37e141a8d74aa53e151c1d1b9a03f88c65adb9e10"),
            Right("26fca7737f48fa702664c8b468e34c858e62f51762386bd0bddaa7050e0dd7c0"),
            Right("e7e11a86a0c1d8d8624b1629cb58e39bb4d0364cb8cb33c4029662ab30336858"),
        ];

        let proof: MerkleProof = proof
            .into_iter()
            .map(|item| item.map(|e_value| e_value.to_string()))
            .collect();

        assert_eq!(tree.proof(3), proof);

        let proof_3 = tree.proof(3);
        let leaf_3 = "3333333333333333333333333333333333333333333333333333333333333333";

        let result = tree.verify(proof_3, leaf_3);
        assert_eq!(result.unwrap(), tree.root());
    }
}
