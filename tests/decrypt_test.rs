use std::fs;
use cryptojs_rust::cryptojs;
use serde_json::Value;

fn load_test_data() -> String {
    fs::read_to_string("tests/get_seats_res.txt")
        .expect("Failed to read test data file")
}

#[test]
fn test_decrypt_seat_data() {
    // Load the encrypted base64 data
    let encrypted_base64 = load_test_data();
    
    // Decrypt the data
    let decrypted_string = cryptojs::decrypt(&encrypted_base64, b"pisaTomer1001")
        .expect("Failed to decrypt data");
    
    // Print just the first 100 characters of the raw string
    println!("Raw decrypted string (first 100 chars): {:?}", 
        &decrypted_string[..100.min(decrypted_string.len())]);

    // Try to parse as JSON to verify it's valid
    let json: Value = serde_json::from_str(&decrypted_string)
        .expect("Failed to parse JSON");
    
    assert!(json.is_array(), "Decrypted data should be a JSON array");
    println!("JSON array successfully parsed. Contains {} elements", 
        json.as_array().unwrap().len());
}