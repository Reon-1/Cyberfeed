use std::io::{self, Write};

struct Attack {
    source_country: String,
    target_country: String,
    attack_type: String,
}

fn main() {
    println!("====================");
    println!("      CYBERFEED");
    println!("====================");

    attack_feed();
    println!("2. Exit");

    print!("Select One Option: ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let user_input = input.trim();

    println!("You chose option {}", user_input);
    println!("-----------------------------");

    // Create first attack
    let first_attack = Attack {
        source_country: String::from("China"),
        target_country: String::from("USA"),
        attack_type: String::from("DDoS"),
    };

    // Create second attack
    let second_attack = Attack {
        source_country: String::from("Russia"),
        target_country: String::from("Germany"),
        attack_type: String::from("Malware"),
    };

    // Create empty list
    let mut attacks: Vec<Attack> = Vec::new();

    // Put both attacks into the list
    attacks.push(first_attack);
    attacks.push(second_attack);

    // Handle user choice
    if user_input == "1" {
        // Go through every attack in the list
        for attack in attacks {
            println!("Source: {}", attack.source_country);
            println!("Target: {}", attack.target_country);
            println!("Type: {}", attack.attack_type);
            println!("-----------------------------");
        }
    } else if user_input == "2" {
        println!("Exit!");
    } else {
        println!("Invalid Choice!");
    }
}

fn attack_feed() {
    println!("1. View attack feed");
}
