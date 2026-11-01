mod app;
mod config;
mod file;
mod http_response;
mod indicator;
mod investigation;
mod log_hunt;
mod providers;
mod report;
mod tui;

use dotenvy::dotenv;
use reqwest::blocking::Client;
use std::time::Duration;

fn main() {
    let _ = dotenv();
    let config = config::Config::from_lookup(|key| std::env::var(key).ok());

    let client = match build_http_client() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("Could not initialize the HTTP client: {error}");
            std::process::exit(1);
        }
    };

    app::run(&client, &config);
}

fn build_http_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .user_agent(concat!("Cyberfeed/", env!("CARGO_PKG_VERSION")))
        .pool_max_idle_per_host(0)
        // Provider requests carry API credentials in headers. Fixed API
        // endpoints do not need redirects, so never forward credentials.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
}

#[cfg(test)]
mod tests {
    use super::build_http_client;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn authenticated_client_does_not_follow_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let redirect_target = TcpListener::bind("127.0.0.1:0").unwrap();
        redirect_target.set_nonblocking(true).unwrap();
        let target_address = redirect_target.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                request.push_str(&line.to_ascii_lowercase());
            }
            assert!(request.contains("auth-key: synthetic-test-key"));
            write!(stream, "HTTP/1.1 302 Found\r\nLocation: http://{target_address}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });

        let response = build_http_client()
            .unwrap()
            .get(format!("http://{address}/api"))
            .header("Auth-Key", "synthetic-test-key")
            .send()
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        server.join().unwrap();
        thread::sleep(Duration::from_millis(50));
        assert!(matches!(
            redirect_target.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
}
