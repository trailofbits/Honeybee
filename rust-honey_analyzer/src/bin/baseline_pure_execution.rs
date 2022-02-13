use std::{path::PathBuf, process::{Command, Child}, os::unix::prelude::CommandExt};

use clap::{self, Arg, ValueHint, AppSettings};
use nix::sys::{personality};
use nix::errno::Errno;

use rust_honey_analyzer::capture_filter::parse_capture_filter;

use std::time::{SystemTime, UNIX_EPOCH};

fn get_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

fn io_error(e: Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(e as i32)
}
fn spawn_suspended(args: &[&str]) -> Result<Child, std::io::Error> {
    let mut cmd = Command::new(args[0]);
        cmd.args(&args[1..]);

    unsafe {
        cmd.pre_exec(|| {
            let old_personality = personality::get().map_err(io_error )?;
            personality::set(old_personality.union(personality::Persona::ADDR_NO_RANDOMIZE))?;
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    Ok(child)
}

fn err_str(e: impl ToString) -> String {
    e.to_string()
}

// fn suspend_process(pid: u32) {
//     ptrace::interrupt(Pid::from_raw(pid as i32)).expect("Could not interrupt child process!");
// }

fn main() -> Result<(), String> {
    let matches = clap::app_from_crate!()
        .setting(AppSettings::TrailingVarArg)
        .arg(
            Arg::new("hive_path")
                .help("Path to the pre-generated hive file for the target binary")
                .value_hint(ValueHint::FilePath)
                .required(true)
                .validator(|s| {
                    let pb = PathBuf::from(s);
                    if !pb.exists() {
                        return Err(format!("Hive file @ {:?} does not exist!", pb))
                    }
                    pb.canonicalize().map_err(err_str)
                })
        )
        .arg(
            Arg::new("filter")
                .required(true)
                .help("Address range to filter")
                .validator(parse_capture_filter)
                .value_hint(ValueHint::Other)
        )
        .arg(Arg::new("command")
            .required(true)
            .takes_value(true)
            .multiple_values(true)
            .value_hint(ValueHint::CommandWithArguments)
            .last(true)
        )
        .get_matches();

    let hive_path: PathBuf = matches.value_of_t("hive_path").unwrap();
    let cmdline = matches.values_of("command").unwrap().collect::<Vec<_>>();

    println!("hive_path={hive_path:?}, filters={:?}, cmdline={cmdline:?}");

    let clk_pre_exec = get_epoch_ms();

    // CAPTURE
    let mut child = spawn_suspended(&cmdline).expect("Could not spawn child process");
    let exit_status = child.wait().expect("Failed to wait for child pid!");
    let clk_post_child_exit = get_epoch_ms();
    println!("Child returned with status code {:?}", exit_status);

    println!("pure execution: {:?}", clk_post_child_exit-clk_pre_exec);

    Ok(())
}