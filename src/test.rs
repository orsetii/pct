fn main() {
    loop {
        {
            let t = if let Some(token) = self.current() {
                token
            } else {
                break;
            };
            println!("{:?}", t);
        }
        let b = self.get();
        println!("{:?}", b);
    }
}
