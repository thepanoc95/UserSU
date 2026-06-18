use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "psu")]
#[command(about = "UserSU Shell & Branch Manager", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Create { name: String },
    Switch { name: String },
    Delete { name: String },
    List,
    Rollback,
    Status,
}

fn main() {
    let cli = Cli::parse();
    let base_dir = Path::new("/data/local/tmp/usersu");
    let branches_dir = base_dir.join("branches");
    let active_link = base_dir.join("active");

    fs::create_dir_all(&branches_dir).unwrap();
    let main_branch = branches_dir.join("main");
    if !main_branch.exists() {
        fs::create_dir_all(&main_branch).unwrap();
        setup_branch_fs(&main_branch);
    }
    if !active_link.exists() {
        let _ = symlink(&main_branch, &active_link);
    }

    match &cli.command {
        Some(Commands::Create { name }) => {
            create_branch(&branches_dir, &active_link, name);
        }
        Some(Commands::Switch { name }) => {
            switch_branch(&branches_dir, &active_link, name);
        }
        Some(Commands::Delete { name }) => {
            delete_branch(&branches_dir, name);
        }
        Some(Commands::List) => {
            list_branches(&branches_dir, &active_link);
        }
        Some(Commands::Rollback) => {
            rollback_branch(&active_link);
        }
        Some(Commands::Status) => {
            status_branch(&active_link);
        }
        None => {
            enter_shell(&active_link);
        }
    }
}

fn setup_branch_fs(branch_dir: &Path) {
    let subdirs = vec![
        "bin", "sbin", "etc", "root", "home", "tmp", 
        "usr/bin", "usr/sbin", "usr/lib", "var"
    ];
    for dir in subdirs {
        fs::create_dir_all(branch_dir.join(dir)).unwrap();
    }

    let sys_bin = Path::new("/system/bin");
    let guest_bin = branch_dir.join("bin");
    if let Ok(entries) = fs::read_dir(sys_bin) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap();
                let _ = symlink(&path, guest_bin.join(file_name));
            }
        }
    }

    let _ = Command::new("git").arg("init").current_dir(branch_dir).status();
    let _ = Command::new("git").args(&["add", "."]).current_dir(branch_dir).status();
    let _ = Command::new("git").args(&["commit", "-m", "Initial rootFS template"]).current_dir(branch_dir).status();
}

fn create_branch(branches_dir: &Path, active_link: &Path, name: &str) {
    let new_branch = branches_dir.join(name);
    if new_branch.exists() {
        println!("Branch '{}' already exists.", name);
        return;
    }
    fs::create_dir_all(&new_branch).unwrap();

    let active_dir = active_link.canonicalize().unwrap();
    copy_dir_recursive(&active_dir, &new_branch);

    let _ = Command::new("git").arg("init").current_dir(&new_branch).status();
    let _ = Command::new("git").args(&["add", "."]).current_dir(&new_branch).status();
    let _ = Command::new("git").args(&["commit", "-m", &format!("Branch created from {:?}", active_dir.file_name().unwrap())]).current_dir(&new_branch).status();
    
    println!("Branch '{}' created successfully.", name);
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    if src.is_symlink() {
        if let Ok(target) = fs::read_link(src) {
            let _ = symlink(target, dst);
        }
    } else if src.is_dir() {
        fs::create_dir_all(dst).unwrap();
        if let Ok(entries) = fs::read_dir(src) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                copy_dir_recursive(&src.join(&name), &dst.join(&name));
            }
        }
    } else {
        let _ = fs::copy(src, dst);
    }
}

fn switch_branch(branches_dir: &Path, active_link: &Path, name: &str) {
    let target = branches_dir.join(name);
    if !target.exists() {
        println!("Branch '{}' does not exist.", name);
        return;
    }
    let _ = fs::remove_file(active_link);
    symlink(&target, active_link).unwrap();
    println!("Switched to branch '{}'.", name);
}

fn delete_branch(branches_dir: &Path, name: &str) {
    if name == "main" {
        println!("Cannot delete main branch.");
        return;
    }
    let target = branches_dir.join(name);
    if !target.exists() {
        println!("Branch '{}' does not exist.", name);
        return;
    }
    fs::remove_dir_all(target).unwrap();
    println!("Branch '{}' deleted.", name);
}

fn list_branches(branches_dir: &Path, active_link: &Path) {
    let active = active_link.canonicalize().unwrap();
    let active_name = active.file_name().unwrap().to_str().unwrap();
    
    if let Ok(entries) = fs::read_dir(branches_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap().to_str().unwrap();
                if name == active_name {
                    println!("* {}", name);
                } else {
                    println!("  {}", name);
                }
            }
        }
    }
}

fn rollback_branch(active_link: &Path) {
    let active = active_link.canonicalize().unwrap();
    let status1 = Command::new("git").args(&["reset", "--hard", "HEAD"]).current_dir(&active).status();
    let status2 = Command::new("git").args(&["clean", "-fd"]).current_dir(&active).status();
    if status1.is_ok() && status2.is_ok() {
        println!("Rollback complete.");
    } else {
        println!("Rollback failed (git might not be installed or initialized).");
    }
}

fn status_branch(active_link: &Path) {
    let active = active_link.canonicalize().unwrap();
    let _ = Command::new("git").arg("status").current_dir(&active).status();
}

fn enter_shell(active_link: &Path) {
    let proot = Path::new("/data/local/tmp/usersu/bin/proot");
    if !proot.exists() {
        println!("PRoot binary not found at /data/local/tmp/usersu/bin/proot");
        return;
    }

    let mut child = Command::new(proot)
        .arg("-r")
        .arg(active_link)
        .arg("-b")
        .arg("/dev")
        .arg("-b")
        .arg("/proc")
        .arg("-b")
        .arg("/sys")
        .arg("-0")
        .arg("/system/bin/sh")
        .spawn()
        .unwrap();

    let _ = child.wait();
}
