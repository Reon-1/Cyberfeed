use std::io::{self, Write};

struct Attack {
    source_country: String,
    target_country: String,
    attack_type: String,
    timestamp: String,
    severity: Severity,
}

enum Severity {
    Low,
    Medium,
    High,
}

fn main() {
    let attacks: Vec<Attack> = get_attacks();

    loop {
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

        // Handle user choice
        if user_input == "1" {
            // length of vector
            let attack_len = attacks.len();
            println!("{} : Attacks Detected", attack_len);

            // Go through every attack in the list
            for attack in &attacks {
                println!("Source: {}", attack.source_country);
                println!("Target: {}", attack.target_country);
                println!("Type: {}", attack.attack_type);
                println!("Time: {}", attack.timestamp);

                match attack.severity {
                    Severity::Low => println!("Severity: Low"),
                    Severity::Medium => println!("Severity: Medium"),
                    Severity::High => println!("Severity: High"),
                }

                println!("-----------------------------");
            }
            println!("Press Enter to Continue");
            io::stdin()
                .read_line(&mut input)
                .expect("Press Enter to Continue");
        } else if user_input == "2" {
            println!("Exit!");
            break;
        } else {
            println!("Invalid Choice!");
        }
    }
}

fn attack_feed() {
    println!("1. View attack feed");
}

fn get_attacks() -> Vec<Attack> {
    // Create first attack
    let first_attack = Attack {
        source_country: String::from("China"),
        target_country: String::from("USA"),
        attack_type: String::from("DDoS"),
        timestamp: String::from("2026-08-20 22:15:11"),
        severity: Severity::Low,
    };

    // Create second attack
    let second_attack = Attack {
        source_country: String::from("Russia"),
        target_country: String::from("Germany"),
        attack_type: String::from("Malware"),
        timestamp: String::from("2026-08-21 10:15:03"),
        severity: Severity::Medium,
    };

    // Create Third attack
    let third_attack = Attack {
        source_country: String::from("North Korea"),
        target_country: String::from("Poland"),
        attack_type: String::from("Trojan"),
        timestamp: String::from("2026-08-22 01:05:22"),
        severity: Severity::High,
    };

    // Create empty list
    let mut attacks: Vec<Attack> = Vec::new();

    // Put attacks into the list
    attacks.push(first_attack);
    attacks.push(second_attack);
    attacks.push(third_attack);
    attacks
}
