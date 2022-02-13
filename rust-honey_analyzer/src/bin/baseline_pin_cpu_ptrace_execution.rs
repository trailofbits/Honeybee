use std::{path::PathBuf, process::{Command, Child}, os::unix::prelude::CommandExt, io::ErrorKind};

use clap::{self, Arg, ValueHint, AppSettings};
use nix::sys::{ptrace, personality};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::signal::Signal;
use nix::errno::Errno;
use nix::unistd::Pid;
use nix::sched::{sched_setaffinity, CpuSet};

use rust_honey_analyzer::{
    capture_filter::parse_capture_filter
};

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
            ptrace::traceme().map_err(io_error)?;
            let old_personality = personality::get().map_err(io_error )?;
            personality::set(old_personality.union(personality::Persona::ADDR_NO_RANDOMIZE))?;
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    let child_pid = child.id();
    let res = waitpid(Pid::from_raw(child_pid as i32), None);
    match res {
        Ok(WaitStatus::Stopped(waited_pid, Signal::SIGTRAP)) => {
            assert!(child_pid == child.id(), "Got SIGTRAP from the wrong process?? child_pid={}, got pid={}", child_pid, waited_pid);
            Ok(child)
        },
        other => Err(
            std::io::Error::new(
                ErrorKind::Other,
                format!("Got incorrect child status: {:?}", other),
            ))
    }
}

fn pin_process_to_cpu(pid: u32, cpu: u16) -> Result<(), Errno>{
    let mut cpuset = CpuSet::new();
    cpuset.set(cpu.try_into().unwrap())?;
    sched_setaffinity(Pid::from_raw(pid.try_into().unwrap()), &cpuset)?;
    Ok(())
}

fn err_str(e: impl ToString) -> String {
    e.to_string()
}

// fn suspend_process(pid: u32) {
//     ptrace::interrupt(Pid::from_raw(pid as i32)).expect("Could not interrupt child process!");
// }

fn unsuspend_process(pid: u32) {
    ptrace::cont(Pid::from_raw(pid as i32), None).expect("Could not continue child process!");
}

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

    let clk_pre_all = get_epoch_ms();

    // CAPTURE
    let mut child = spawn_suspended(&cmdline).expect("Could not spawn child process");
    pin_process_to_cpu(child.id(), 0u16).expect("Could not pin child process to CPU #0");

    let clk_pre_unsuspend = get_epoch_ms();
    unsuspend_process(child.id());

    let exit_status = child.wait().expect("Failed to wait for child pid!");
    println!("Child exited with status {:?}", exit_status);
    let clk_post_child_exit = get_epoch_ms();

    let timestamps = [clk_pre_all, clk_pre_unsuspend, clk_post_child_exit];
    // let timestamps = timestamps[1..].iter()
    //     .map(|curr| curr - timestamps[0])
    //     .collect::<Vec<_>>();
    let timestamps = timestamps[..timestamps.len()-1].iter()
        .zip(timestamps[1..].iter())
        .map(|(prev, curr)| curr - prev)
        .zip(&["spawn & pin", "child_execution"])
        .collect::<Vec<_>>();
    println!("timestamps: {:?}", timestamps);

    Ok(())
}