use std::sync::RwLock;

// TODO: In practice, there should be a trait AppendOnlyTxnStore that has methods `append`, `size`
// and `get_many` which `InMemoryAppendOnlyTxnStore` implements

/// Stores incoming transactions as bytes instead of base64 encoded string. This tradeoff is made to
/// reduce the amount of memory being used for some CPU time when a transaction has to be signed.
/// An optimization would be have another storage where frequently (or recently, depends on the
/// application) used transactions are kept serialized
pub struct InMemoryAppendOnlyTxnStore {
    transactions: RwLock<Vec<Vec<u8>>>,
}

impl InMemoryAppendOnlyTxnStore {
    pub fn new() -> Self {
        InMemoryAppendOnlyTxnStore {
            transactions: RwLock::new(vec![]),
        }
    }

    /// Append a transaction to the store and return its id
    pub fn append(&self, txn: Vec<u8>) -> usize {
        let mut store = self.transactions.write().unwrap();
        let id = store.len();
        store.push(txn);
        id
    }

    /// Return number of transactions in the store.
    pub fn size(&self) -> usize {
        let store = self.transactions.read().unwrap();
        store.len()
    }

    /// Return transactions with given ids. Assuming all ids are valid since input validation has
    /// been done by the server.
    pub fn get_many(&self, ids: &[usize]) -> Vec<Vec<u8>> {
        let mut txns = vec![];
        let store = self.transactions.read().unwrap();
        for id in ids {
            txns.push(store[*id].clone());
        }
        txns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_append_only_store() {
        let store = InMemoryAppendOnlyTxnStore::new();
        assert_eq!(store.append(vec![1, 2]), 0);
        assert_eq!(store.append(vec![2, 3, 4]), 1);
        assert_eq!(store.append(vec![5]), 2);
        assert_eq!(store.append(vec![1, 2]), 3);
        assert_eq!(store.append(vec![1, 2, 8, 9]), 4);

        assert_eq!(store.size(), 5);

        assert_eq!(store.get_many(&vec![0]), vec![vec![1, 2]]);
        assert_eq!(store.get_many(&vec![2]), vec![vec![5]]);
        assert_eq!(store.get_many(&vec![0, 3]), vec![vec![1, 2], vec![1, 2]]);
    }
}
