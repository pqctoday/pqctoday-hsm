use xmss::{Xmss, XmssParams, Sha2_256};
use rand_core::SeedableRng;
fn main() {
    let params = XmssParams::Sha2_10_256;
    println!("{:?}", params);
}
