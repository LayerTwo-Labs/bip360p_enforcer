pub fn bdk_txid_to_bitcoin_txid(txid: bdk_wallet::bitcoin::Txid) -> bitcoin::Txid {
    use bdk_wallet::bitcoin::hashes::Hash as _;
    let bytes = txid.to_byte_array();

    use bitcoin::hashes::sha256d::Hash;
    let hash: bitcoin::hashes::sha256d::Hash = Hash::from_byte_array(bytes);

    bitcoin::Txid::from_raw_hash(hash)
}
