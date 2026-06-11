use std::fs;
use std::path::Path;
use std::process::Command;
use std::env;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        println!("Usage: psudo <command> [args...]");
        return;
    }

    let active_link = Path::new("/data/local/tmp/usersu/active");
    let proot = Path::new("/data/local/tmp/usersu/bin/proot");
    if !proot.exists() {
        println!("PRoot binary not found at /data/local/tmp/usersu/bin/proot");
        return;
    }

    let mut cmd = Command::new(proot);
    cmd.arg("-r")
       .arg(active_link)
       .arg("-b")
       .arg("/dev")
       .arg("-b")
       .arg("/proc")
       .arg("-b")
       .arg("/sys")
       .arg("-0");

    for arg in args {
        cmd.arg(arg);
    }

    let mut child = cmd.spawn().expect("Failed to execute command inside sandbox");
    let status = child.wait().expect("Command did not run successfully");
    std::process::exit(status.code().unwrap_or(1));
}
