/// Convert ISO 3166-1 alpha-2 country code to flag emoji
pub fn country_code_to_flag(code: &str) -> String {
    let code = code.to_uppercase();
    if code.len() != 2 {
        return "🏳️".to_string();
    }
    let mut flag = String::new();
    for c in code.chars() {
        if !c.is_ascii_alphabetic() {
            return "🏳️".to_string();
        }
        let base: u32 = 0x1F1E6; // Regional indicator A
        let offset = (c as u32) - ('A' as u32);
        if let Some(ch) = char::from_u32(base + offset) {
            flag.push(ch);
        }
    }
    if flag.chars().count() == 2 {
        flag
    } else {
        "🏳️".to_string()
    }
}
