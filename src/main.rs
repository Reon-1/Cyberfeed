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
    // Get all attacks when the program starts
    let attacks: Vec<Attack> = get_attacks();

    loop {
        println!("====================");
        println!("      CYBERFEED");
        println!("====================");

        // Display the available menu options
        attack_feed();

        print!("Select One Option: ");

        // Make sure the prompt appears before waiting for input
        io::stdout().flush().expect("Failed to flush stdout");

        let mut input = String::new();

        // Read the user's input
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        // Remove whitespace and the newline from the input
        let user_input = input.trim();

        println!("You chose option {}", user_input);
        println!("-----------------------------");

        // Handle user choice
        if user_input == "1" {
            // Get the length of the vector
            let attack_len = attacks.len();

            println!("{} : Attacks Detected", attack_len);
            println!("-----------------------------");

            // Display every attack
            display_all_attacks(&attacks);

            println!("Press Enter to Continue");

            io::stdin()
                .read_line(&mut input)
                .expect("Press Enter to Continue");
        } else if user_input == "2" {
            // Find and display only High severity attacks
            let high_count = high_severity_attacks(&attacks);

            println!("{} High Severity Attacks Detected", high_count);

            println!("Press Enter to Continue");

            io::stdin()
                .read_line(&mut input)
                .expect("Press Enter to Continue");
        } else if user_input == "3" {
            // Exit the program
            println!("Exit!");
            break;
        } else {
            // Handle anything other than 1, 2, or 3
            println!("Invalid Choice!");
        }
    }
}

fn attack_feed() {
    // Display the available options
    println!("1. View all attacks");
    println!("2. View high severity attacks");
    println!("3. Exit");
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

    // Create third attack
    let third_attack = Attack {
        source_country: String::from("North Korea"),
        target_country: String::from("Poland"),
        attack_type: String::from("Trojan"),
        timestamp: String::from("2026-08-22 01:05:22"),
        severity: Severity::High,
    };

    // Create an empty list of attacks
    let mut attacks: Vec<Attack> = Vec::new();

    // Put the attacks into the list
    attacks.push(first_attack);
    attacks.push(second_attack);
    attacks.push(third_attack);

    // Return the completed list
    attacks
}

fn display_attack(attack: &Attack) {
    // Display information about one attack
    println!("Source: {}", attack.source_country);
    println!("Target: {}", attack.target_country);
    println!("Type: {}", attack.attack_type);
    println!("Time: {}", attack.timestamp);

    // Display the severity of the attack
    match attack.severity {
        Severity::Low => println!("Severity: Low"),
        Severity::Medium => println!("Severity: Medium"),
        Severity::High => println!("Severity: High"),
    }

    println!("-----------------------------");
}

fn display_all_attacks(attacks: &Vec<Attack>) {
    // Go through every attack in the list
    for attack in attacks {
        // Display the current attack
        display_attack(attack);
    }
}

fn high_severity_attacks(attacks: &Vec<Attack>) -> i32 {
    // Keep track of how many High severity attacks we find
    let mut high_count: i32 = 0;

    // Go through every attack in the list
    for attack in attacks {
        // Check the severity of each attack
        match attack.severity {
            // Only display High severity attacks
            Severity::High => {
                // Increase the counter
                high_count += 1;

                // Display the current attack
                display_attack(attack);
            }

            // Ignore Low and Medium attacks
            _ => {}
        }
    }
    // Return the number of High severity attacks
    high_count
}
