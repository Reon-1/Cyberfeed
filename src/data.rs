use crate::attack::Attack;
use std::fs;

pub fn load_attacks() -> Vec<Attack> {
    let data = fs::read_to_string("src/attacks.json").expect("Failed to read attacks.json");

    let attacks: Vec<Attack> = serde_json::from_str(&data).expect("Failed to parse attacks.json");

    attacks
}
