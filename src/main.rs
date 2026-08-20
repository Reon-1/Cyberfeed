use std::io::{self, Write};

struct Attack {
    source_country: String,
    target_country: String,
    attack_type: String,
}

fn main() {
    println!(
        "====================
      CYBERFEED
===================="
    );
    attack_feed();
    println!("2. Exit");

    // print a prompt in the terminal
    print!("Select One Option:");
    io::stdout().flush().expect("Selected:");

    //Create mutable String buffer to hold the input
    let mut input = String::new();

    // Read the lines from the keyboard
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    // Trim the invisible trailing newlines etc
    let trimmed_input = input.trim();
    println!("You Choose Option {}", trimmed_input);

    //user input choice
    if trimmed_input == "1" {
        println!("More options:");
    } else if trimmed_input == "2" {
        println!("Exit!");
    } else {
        println!("Invalid Choice!!");
    }

    let attack_info = Attack {
        source_country: String::from("China"),
        target_country: String::from("USA"),
        attack_type: String::from("DDOS"),
    };

    println!("Source: {}", attack_info.source_country);
    println!("Target: {}", attack_info.target_country);
    println!("Type: {}", attack_info.attack_type);
}

fn attack_feed() {
    println!("1. View attack feed");
}
