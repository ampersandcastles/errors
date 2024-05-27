use std::fs::File;
use std::io::{self, BufRead, Read};
use std::net::TcpStream;
use ssh2::Session;
use csv::Writer;
use serde::Serialize;
use thiserror::Error;
use serde_json::Value;
use regex::Regex;
use std::collections::HashSet;

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
    log_file: String,
    error_type: String,
    error_message: String,
}

fn read_ip_list(filename: &str) -> Result<Vec<String>, CustomError> {
    println!("Reading IP list from {}", filename);
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    let ip_list = reader.lines().collect::<Result<Vec<_>, _>>()?;
    println!("Found {} IPs", ip_list.len());
    Ok(ip_list)
}

fn load_json_file(filename: &str) -> Result<Value, CustomError> {
    println!("Loading JSON file from {}", filename);
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    let json_data: Value = serde_json::from_reader(reader)?;
    println!("Loaded JSON data from {}", filename);
    Ok(json_data)
}

fn ssh_connect(ip: &str, username: &str, password: &str) -> Result<Session, CustomError> {
    println!("Connecting to {} with username: {}", ip, username);
    let tcp = TcpStream::connect(format!("{}:22", ip))?;
    let mut session = Session::new()?;
    session.set_tcp_stream(tcp);
    session.handshake()?;
    session.userauth_password(username, password)?;
    println!("Successfully connected to {}", ip);
    Ok(session)
}

fn list_log_files(session: &Session) -> Result<Vec<String>, CustomError> {
    println!("Listing log files");
    let mut channel = session.channel_session()?;
    channel.exec("find /var/log/ -type f")?;
    let mut s = String::new();
    channel.read_to_string(&mut s)?;
    channel.wait_close()?;
    let log_files: Vec<String> = s.lines().map(|line| line.to_string()).collect();
    println!("Found {} log files", log_files.len());
    Ok(log_files)
}

fn read_log_file(session: &Session, file: &str) -> Result<String, CustomError> {
    println!("Reading log file: {}", file);
    let mut channel = session.channel_session()?;
    channel.exec(&format!("cat {}", file))?;
    let mut buffer = Vec::new();
    channel.read_to_end(&mut buffer)?;
    channel.wait_close()?;
    match String::from_utf8(buffer) {
        Ok(content) => Ok(content),
        Err(_) => {
            println!("Skipping non-UTF-8 log file: {}", file);
            Err(CustomError::IoError(io::Error::new(io::ErrorKind::InvalidData, "stream did not contain valid UTF-8")))
        },
    }
}

fn check_logs(session: &Session, error_keywords: &Value, patterns: &[Regex]) -> Result<Vec<MachineError>, CustomError> {
    let log_files = list_log_files(session)?;
    let mut errors = Vec::new();
    let mut seen_errors = HashSet::new();
    
    for file in log_files {
        let log_content = match read_log_file(session, &file) {
            Ok(content) => content,
            Err(_) => continue,
        };
        
        for (keyword, error_type) in error_keywords.as_object().unwrap() {
            if log_content.contains(keyword) {
                let error_message = format!("{} in {}", keyword, file);
                if seen_errors.insert(error_message.clone()) {
                    println!("Found keyword '{}' in file '{}'", keyword, file);
                    errors.push(MachineError {
                        worker_name: String::new(),
                        ip: String::new(),
                        log_file: file.clone(),
                        error_type: error_type.as_str().unwrap().to_string(),
                        error_message: keyword.to_string(),
                    });
                }
            }
        }

        for pattern in patterns {
            for cap in pattern.captures_iter(&log_content) {
                if cap.len() > 2 {  // Ensure there are enough groups captured
                    let chain = &cap[1];
                    let asic_count = &cap[2].parse::<i32>().unwrap_or(0);
                    if *asic_count == 0 || (pattern.as_str() == r"Chain (\d+) only find (\d+) asic, will power off hash board (\d+)" && *asic_count < 120) {  // Adjust the threshold as per your requirement
                        let error_message = format!("Chain {}: found {} ASICs in {}", chain, asic_count, file);
                        if seen_errors.insert(error_message.clone()) {
                            println!("Found pattern match in file '{}': Chain {}: found {} ASICs", file, chain, asic_count);
                            errors.push(MachineError {
                                worker_name: String::new(),
                                ip: String::new(),
                                log_file: file.clone(),
                                error_type: "ASIC Error".to_string(),
                                error_message: format!("Chain {}: found {} ASICs", chain, asic_count),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(errors)
}

fn get_worker_name(session: &Session) -> Result<String, CustomError> {
    println!("Getting worker name");
    let mut channel = session.channel_session()?;
    channel.exec("cat /config/cgminer.conf")?;
    let mut s = String::new();
    channel.read_to_string(&mut s)?;
    channel.wait_close()?;
    
    let re = Regex::new(r#""user" *: *"[^.]*\.(\w+)""#).unwrap();
    if let Some(cap) = re.captures(&s) {
        println!("Found worker name: {}", &cap[1]);
        Ok(cap[1].to_string())
    } else {
        println!("Worker name not found");
        Err(CustomError::IoError(io::Error::new(io::ErrorKind::Other, "Worker name not found")))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting log scanner");
    let ip_list = read_ip_list("ips.txt")?;
    let credentials = load_json_file("credentials.json")?;
    let error_keywords = load_json_file("errors.json")?.get("error_keywords").unwrap().clone();
    
    let asic_pattern = Regex::new(r"Chain\[(\d+)\]: find (\d+) asic, times \d+").unwrap();
    let power_off_pattern = Regex::new(r"Chain (\d+) only find (\d+) asic, will power off hash board (\d+)").unwrap();
    let eeprom_error_pattern = Regex::new(r"Data load fail for chain (\d+)\.").unwrap();
    let chip_bin_pattern = Regex::new(r"No chip bin, chain = (\d+)").unwrap();
    let patterns = vec![asic_pattern, power_off_pattern, eeprom_error_pattern, chip_bin_pattern];
    
    let mut results = Vec::new();
    for ip in ip_list {
        println!("Processing IP: {}", ip);
        let mut connected = false;
        for (_os_type, creds) in credentials.as_object().unwrap() {
            for cred in creds.as_array().unwrap() {
                let username = cred[0].as_str().unwrap();
                let password = cred[1].as_str().unwrap();
                match ssh_connect(&ip, username, password) {
                    Ok(session) => {
                        connected = true;
                        let worker_name = get_worker_name(&session).unwrap_or("Unknown".to_string());
                        println!("Worker name: {}", worker_name);
                        let mut logs = check_logs(&session, &error_keywords, &patterns)?;
                        for log in &mut logs {
                            log.worker_name = worker_name.clone();
                            log.ip = ip.clone();
                        }
                        results.extend(logs);
                        break;
                    }
                    Err(e) => {
                        println!("Failed to connect to {} with {}: {}", ip, username, e);
                        continue;
                    }
                }
            }
            if connected { break; }
        }
        if !connected {
            println!("Could not connect to {} with any provided credentials.", ip);
        }
    }

    println!("Writing results to CSV");
    let mut wtr = Writer::from_path("results.csv")?;
    wtr.write_record(&["Worker ID", "IP Address", "Log File", "Error Type", "Error Message"])?;
    for result in results {
        wtr.serialize(result)?;
    }
    wtr.flush()?;
    println!("Done");
    Ok(())
}
