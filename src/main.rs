use std::fs::File;
use std::io::{self, BufRead, Read};
use std::net::TcpStream;
use ssh2::Session;
use csv::Writer;
use serde::Serialize;
use thiserror::Error;
use serde_json::Value;

#[derive(Error, Debug)]
enum CustomError {
    #[error("SSH Error")]
    SshError(#[from] ssh2::Error),
    
    #[error("IO Error")]
    IoError(#[from] io::Error),

    #[error("JSON Error")]
    JsonError(#[from] serde_json::Error),
}

#[derive(Serialize)]
struct MachineError {
    worker_name: String,
    ip: String,
    error: String,
}

fn read_ip_list(filename: &str) -> Result<Vec<String>, CustomError> {
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    let ip_list = reader.lines().collect::<Result<Vec<_>, _>>()?;
    Ok(ip_list)
}

fn ssh_connect(ip: &str, username: &str, password: &str) -> Result<Session, CustomError> {
    let tcp = TcpStream::connect(format!("{}:22", ip))?;
    let mut session = Session::new()?;
    session.set_tcp_stream(tcp);
    session.handshake()?;
    session.userauth_password(username, password)?;
    println!("Successfully connected to {}", ip); // Debugging line
    Ok(session)
}

fn list_log_files(session: &Session) -> Result<Vec<String>, CustomError> {
    let mut channel = session.channel_session()?;
    channel.exec("ls /var/log/")?;
    let mut s = String::new();
    channel.read_to_string(&mut s)?;
    channel.wait_close()?;
    Ok(s.lines().map(|line| line.to_string()).collect())
}

fn read_log_file(session: &Session, file: &str) -> Result<String, CustomError> {
    let mut channel = session.channel_session()?;
    channel.exec(&format!("cat /var/log/{}", file))?;
    let mut s = String::new();
    channel.read_to_string(&mut s)?;
    channel.wait_close()?;
    Ok(s)
}

fn check_logs(session: &Session) -> Result<Vec<String>, CustomError> {
    let log_files = list_log_files(session)?;
    let mut logs = Vec::new();
    for file in log_files {
        match read_log_file(session, &file) {
            Ok(content) => logs.push(content),
            Err(e) => println!("Failed to read log file {}: {:?}", file, e), // Debugging line
        }
    }
    Ok(logs)
}

fn get_worker_name(session: &Session) -> Result<String, CustomError> {
    let mut channel = session.channel_session()?;
    channel.exec("cat /config/cgminer.conf")?;
    let mut s = String::new();
    channel.read_to_string(&mut s)?;
    channel.wait_close()?;
    
    let v: Value = serde_json::from_str(&s)?;
    if let Some(pools) = v.get("pools").and_then(|p| p.as_array()) {
        for pool in pools {
            if let Some(user) = pool.get("user").and_then(|u| u.as_str()) {
                if let Some(worker_id) = user.split('.').last() {
                    return Ok(worker_id.to_string());
                }
            }
        }
    }
    Err(CustomError::IoError(io::Error::new(io::ErrorKind::Other, "Worker name not found")))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ip_list = read_ip_list("ips.txt")?;
    let mut wtr = Writer::from_path("errors.csv")?;

    let error_patterns = vec![
        "ERROR_TEMP_TOO_HIGH",
        "ERROR_HASHRATE_TOO_LOW",
        "ERROR_NETWORK_DISCONNECTED",
        "ERROR_POWER_LOST: power voltage rise or drop",
        "SWEEP_STRING",
        "_pic_write_iic failed!",
        "The dragons are here.",
        // Add more error patterns here
    ];

    for ip in ip_list {
        let credentials = vec![
            ("root", "root"), // Stock Antminer and Braiins
            ("miner", "miner"),
            ("admin", "admin")
            // Add other credentials here
        ];

        let mut error_found = String::new();
        let mut worker_name = String::new();

        for (username, password) in &credentials {
            match ssh_connect(&ip, username, password) {
                Ok(session) => {
                    worker_name = match get_worker_name(&session) {
                        Ok(name) => name,
                        Err(e) => {
                            println!("Failed to retrieve worker name from {}: {:?}", ip, e);
                            continue;
                        }
                    };

                    match check_logs(&session) {
                        Ok(logs) => {
                            for log in logs {
                                // println!("Logs for {}: {}", ip, log); // Debugging line
                                for pattern in &error_patterns {
                                    if log.contains(pattern) {
                                        error_found = pattern.to_string();
                                        println!("Error found on {}: {}", ip, error_found); // Debugging line
                                        break;
                                    }
                                }
                                if !error_found.is_empty() {
                                    break;
                                }
                            }
                            if error_found.is_empty() {
                                println!("No errors found on {}.", ip); // Debugging line
                            }
                        }
                        Err(e) => println!("Failed to retrieve logs from {}: {:?}", ip, e), // Debugging line
                    }
                    break;
                }
                Err(e) => println!("Failed to connect to {}: {:?}", ip, e), // Debugging line
            }
        }

        if !error_found.is_empty() {
            wtr.serialize(MachineError {
                worker_name: worker_name.clone(),
                ip: ip.clone(),
                error: error_found,
            })?;
        }
    }

    wtr.flush()?;
    Ok(())
}
