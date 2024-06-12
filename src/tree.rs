const MAX_DEPTH: usize = 30;
const ROOT_INDEX: usize = 0;

#[derive(Default, Debug)]
pub struct MerkleTree {
    depth: usize,
    size: usize,
    store: Vec<Vec<u8>>,
}

impl MerkleTree {
    pub fn new(depth: usize, _initial_value: &str) -> Self {
        let tree = Default::default();

        if depth > MAX_DEPTH {
            eprintln!("Specified depth must be less than 30");
            return tree
        }

        let tree_size = |depth: usize| { usize::pow(2, depth as u32) - 1 };
        let size = tree_size(depth);

        let store = vec![];

        Self {
            depth,
            size,
            store,
        }
    }

    /******************* Index API functions ********************/

    pub fn index(&self, depth: usize, offset: usize) -> usize {
        let index = usize::pow(2, depth as u32) - 1 + offset; // (2,0) => 2^depth -1 + offset => 2^2 - 1 + 0 => 3 index

        if index >= self.size { eprintln!("Index is too large, and does not exist in tree"); return ROOT_INDEX }

        index
    }

    pub fn parent_index(&self, index: usize) -> usize {
        if index == 0 || index > self.size { return ROOT_INDEX }

        match index % 2 {
            0 => (index - 2) / 2,
            1 => (index - 1) / 2,
            _ => unreachable!()
        }
    }

    pub fn left_child_index(&self, index: usize) -> usize {
        let child_index = 2 * index + 1;
        if child_index >= self.size { eprintln!("Child index is too large, and does not exist in tree"); return ROOT_INDEX }
        child_index
    }

    pub fn right_child_index(&self, index: usize) -> usize {
        let child_index = 2 * index + 2;

        if child_index >= self.size { eprintln!("Child index is too large, and does not exist in tree"); return ROOT_INDEX }
        child_index
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn parent_test() {
        let tree: MerkleTree = MerkleTree::new(5, "abcde");

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
}
