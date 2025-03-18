fn main() {
    let string_value = String::from("Hello, world!"); // Create a String
    let str_slice: &str = &string_value; // Borrow it as &str

    println!("String: {}", string_value); // You can still use the String
    println!("&str: {}", str_slice); // Use the &str slice
}
