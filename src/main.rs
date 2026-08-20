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

    let trimmed_input = input.trim();

    println!("You chose option {}", trimmed_input);
    println!("-----------------------------");

    // One Attack
    let first_attack = Attack {
        source_country: String::from("China"),
        target_country: String::from("USA"),
        attack_type: String::from("DDoS"),
    };

    let second_attack = Attack {
        source_country: String::from("Russia"),
        target_country: String::from("Germany"),
        attack_type: String::from("Malware"),
    };

    // list of Attacks
    let mut attacks: Vec<Attack> = Vec::new();

    if trimmed_input == "1" {
        attacks.push(first_attack);
        println!("Source: {}", attacks[0].source_country);
        println!("Target: {}", attacks[0].target_country);
        println!("Type: {}", attacks[0].attack_type);

        println!("-----------------------------");

        attacks.push(second_attack);
        println!("Source: {}", attacks[1].source_country);
        println!("Target: {}", attacks[1].target_country);
        println!("Type: {}", attacks[1].attack_type);
    } else if trimmed_input == "2" {
        println!("Exit!");
    } else {
        println!("Invalid Choice!");
    }
}

fn attack_feed() {
    println!("1. View attack feed");
}
