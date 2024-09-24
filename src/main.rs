use std::{
    env::args,
    fs::{read_to_string, OpenOptions},
    io::{BufWriter, Read, Write},
    net::{Ipv4Addr, TcpStream},
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use rayon::iter::{IntoParallelIterator, ParallelIterator};

pub struct VNCInfo {
    ip: Ipv4Addr,
    version: String,
    no_auth: bool,
}

fn check_vnc(ip: Ipv4Addr) -> anyhow::Result<VNCInfo> {
    let mut stream = TcpStream::connect((ip, 5900))?;
    stream.set_read_timeout(Some(Duration::from_millis(6000)))?;

    let mut rfb_version = [0; 12];
    stream.read_exact(&mut rfb_version)?;

    if !rfb_version.starts_with(b"RFB") {
        anyhow::bail!("rfb_version does not start with RFB");
    }

    // send back the rfb version
    stream.write_all(&rfb_version)?;

    let mut num_of_auth = [0; 1];
    stream.read_exact(&mut num_of_auth)?;

    let mut is_noauth = false;
    let num_of_auth = num_of_auth[0] as usize;
    for _ in 0..num_of_auth {
        let mut auth_method = [0; 1];
        stream.read_exact(&mut auth_method)?;
        if auth_method[0] == 1 {
            is_noauth = true;
            break;
        }
    }

    Ok(VNCInfo {
        ip,
        version: String::from_utf8_lossy(&rfb_version).to_string(),
        no_auth: is_noauth,
    })
}

fn main() -> anyhow::Result<()> {
    let args = args().skip(1).collect::<Vec<String>>();
    let filename = args
        .get(0)
        .expect("expected file with IPs to scan, separated by newlines");
    let path = Path::new(filename);
    let content = read_to_string(path)?;

    let ips = content
        .split_whitespace()
        .map(|x| Ipv4Addr::from_str(x).expect(&format!("failed to parse ipv4 address: {x}")))
        .collect::<Vec<Ipv4Addr>>();

    let matched_ips = Arc::new(Mutex::new(Vec::new()));

    ips.into_par_iter().for_each(|x| {
        if let Ok(info) = check_vnc(x) {
            println!(
                "{} - {} - no auth: {}",
                info.ip,
                info.version.trim_end(),
                info.no_auth
            );

            if info.no_auth {
                let mut lock = matched_ips.lock().unwrap();
                lock.push(info);
            }
        }
        //else {
        // println!("failed to connect to {x}");
        //}
    });

    let ips = matched_ips.lock().unwrap();
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open("no_auth_vncs.txt")?;
    let mut buf_writer = BufWriter::new(file);

    for info in ips.iter() {
        let data = format!("{}\n", info.ip);
        buf_writer.write_all(data.as_bytes())?;
    }

    buf_writer.flush()?;

    Ok(())
}
