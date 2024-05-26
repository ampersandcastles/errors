use std::fs::File;
use std::io::{self, BufRead, Read};
use std::net::TcpStream;
use ssh2::Session;
use csv::Writer;
use serde::Serialize;
use thiserror::Error;
use serde_json::Value;
use regex::Regex;

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
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    let ip_list = reader.lines().collect::<Result<Vec<_>, _>>()?;
    Ok(ip_list)
}

fn load_json_file(filename: &str) -> Result<Value, CustomError> {
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    let json_data: Value = serde_json::from_reader(reader)?;
    Ok(json_data)
}

fn ssh_connect(ip: &str, username: &str, password: &str) -> Result<Session, CustomError> {
    let tcp = TcpStream::connect(format!("{}:22", ip))?;
    let mut session = Session::new()?;
    session.set_tcp_stream(tcp);
    session.handshake()?;
    session.userauth_password(username, password)?;
    Ok(session)
}

fn list_log_files(session: &Session) -> Result<Vec<String>, CustomError> {
    let mut channel = session.channel_session()?;
    channel.exec("find /var/log/ -type f")?;
    let mut s = String::new();
    channel.read_to_string(&mut s)?;
    channel.wait_close()?;
    Ok(s.lines().map(|line| line.to_string()).collect())
}

fn read_log_file(session: &Session, file: &str) -> Result<String, CustomError> {
    let mut channel = session.channel_session()?;
    channel.exec(&format!("cat {}", file))?;
    let mut buffer = Vec::new();
    channel.read_to_end(&mut buffer)?;
    channel.wait_close()?;
    match String::from_utf8(buffer) {
        Ok(content) => Ok(content),
        Err(_) => Err(CustomError::IoError(io::Error::new(io::ErrorKind::InvalidData, "stream did not contain valid UTF-8"))),
    }
}

fn check_logs(session: &Session, error_keywords: &Value, patterns: &[Regex]) -> Result<Vec<MachineError>, CustomError> {
    let log_files = list_log_files(session)?;
    let mut errors = Vec::new();
    
    for file in log_files {
        let log_content = match read_log_file(session, &file) {
            Ok(content) => content,
            Err(_) => continue,
        };
        
        for (keyword, error_type) in error_keywords.as_object().unwrap() {
            if log_content.contains(keyword) {
                errors.push(MachineError {
                    worker_name: String::new(),
                    ip: String::new(),
                    log_file: file.clone(),
                    error_type: error_type.as_str().unwrap().to_string(),
                    error_message: keyword.to_string(),
                });
            }
        }

        for pattern in patterns {
            for cap in pattern.captures_iter(&log_content) {
                if cap.len() > 2 {  // Ensure there are enough groups captured
                    errors.push(MachineError {
                        worker_name: String::new(),
                        ip: String::new(),
                        log_file: file.clone(),
                        error_type: "ASIC Error".to_string(),
                        error_message: format!("Chain {}: found {} ASICs", &cap[1], &cap[2]),
                    });
                }
            }
        }
    }

    Ok(errors)
}

fn get_worker_name(session: &Session) -> Result<String, CustomError> {
    let mut channel = session.channel_session()?;
    channel.exec("cat /config/cgminer.conf")?;
    let mut s = String::new();
    channel.read_to_string(&mut s)?;
    channel.wait_close()?;
    
    let re = Regex::new(r#""user" *: *"[^.]*\.(\w+)""#).unwrap();
    if let Some(cap) = re.captures(&s) {
        Ok(cap[1].to_string())
    } else {
        Err(CustomError::IoError(io::Error::new(io::ErrorKind::Other, "Worker name not found")))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
        let mut connected = false;
        for (_os_type, creds) in credentials.as_object().unwrap() {
            for cred in creds.as_array().unwrap() {
                let username = cred[0].as_str().unwrap();
                let password = cred[1].as_str().unwrap();
                match ssh_connect(&ip, username, password) {
                    Ok(session) => {
                        connected = true;
                        let worker_name = get_worker_name(&session).unwrap_or("Unknown".to_string());
                        let mut logs = check_logs(&session, &error_keywords, &patterns)?;
                        for log in &mut logs {
                            log.worker_name = worker_name.clone();
                            log.ip = ip.clone();
                        }
                        results.extend(logs);
                        break;
                    }
                    Err(_) => continue,
                }
            }
            if connected { break; }
        }
    }

    let mut wtr = Writer::from_path("results.csv")?;
    wtr.write_record(&["Worker ID", "IP Address", "Log File", "Error Type", "Error Message"])?;
    for result in results {
        wtr.serialize(result)?;
    }
    wtr.flush()?;
    Ok(())
}
