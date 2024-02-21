pub struct ExtensionNodeCircuit {}

#[cfg(test)]
mod test {
    fn len() {
        let k = random_vector(32);
        let v = random_vector(32);
        let encoded = rlp::encode_list(&[&k, &v]);
        println!("encoded: {:?}", encoded.len());
    }
}
