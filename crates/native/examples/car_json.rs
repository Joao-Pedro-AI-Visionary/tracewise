//! Print the records of an Assets.car as the JSON array that assetutil --info would print.
fn main() {
    let path = std::env::args().nth(1).expect("path");
    let data = std::fs::read(&path).expect("read");
    let records = tracewise_native::car::read_catalog(&data).expect("decode");
    println!("{}", serde_json::to_string(&records).unwrap());
}
