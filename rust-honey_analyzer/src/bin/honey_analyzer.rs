use std::{path::PathBuf, os::unix::prelude::CommandExt, io::ErrorKind};
use std::process::{Command, Child};
use std::io::Write;

use clap::{self, Arg, ValueHint, AppSettings};
use libc::pid_t;
use nix::sys::{ptrace, personality, signal::Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::errno::Errno;
use nix::unistd::Pid;
use nix::sched::{sched_setaffinity, CpuSet};

use rust_honey_analyzer::example_coverage_info::{CoverageTracker, FullTrace64Bit, TrivialDedupFullTrace64Bit, FullTrace32Bit, TrivialDedupFullTrace32Bit, LessTrivialDedupFullTrace32Bit, XorDiffULeb128CompressedTrace, BlockBTreeSetCoverageInfo, BlockHashSetCoverageInfo, EdgeBTreeSetCoverageInfo, EdgeHashSetCoverageInfo};
use rust_honey_analyzer::hive::HoneyBeeHive;
use rust_honey_analyzer::capture_session::CaptureSession;
use rust_honey_analyzer::capture_filter::parse_capture_filter;
use rust_honey_analyzer::analysis_session::AnalysisSession;

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

fn pin_process_to_cpu(pid: u32, cpu: u16) {
    let mut cpuset = CpuSet::new();
    cpuset.set(cpu as usize).expect("Could not set CPU in set?");
    sched_setaffinity(Pid::from_raw(pid as pid_t), &cpuset).expect("Could not set cpu affinity??");
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

fn append_to_file(path: &str, content: &str) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(path)
        .unwrap();
    write!(file, "{}", content).unwrap();
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
        .arg(
            Arg::new("global_buffer_count")
                .default_value("400")
                .help("the number of ToPA entries to allocate per CPU")
                .short('c')
                .long("buffer_count")
                .validator(|s| s.parse::<u32>())
                .value_hint(ValueHint::Other)
        )
        .arg(
            Arg::new("page_power")
                .default_value("5")
                .help("2**page_power ToPA pages will be allocated")
                .short('p')
                .long("page_power")
                .validator(|s| s.parse::<u8>())
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
    let filter = parse_capture_filter(matches.value_of("filter").expect("filter must be provided"))?;
    let cmdline = matches.values_of("command").unwrap().collect::<Vec<_>>();
    let buffer_count: u32 = matches.value_of_t("global_buffer_count").unwrap();
    let page_power: u8 = matches.value_of_t("page_power").unwrap();

    println!("hive_path={hive_path:?}, filters={:?}, cmdline={cmdline:?}");

    let clk_pre_all = get_epoch_ms();

    let hive = HoneyBeeHive::load(
        hive_path.as_os_str().to_str().expect("hive_path is not valid UTF-8, could not be decoded!")
    )
        .expect("Could not open Hive file!");

    let clk_post_hive_load = get_epoch_ms();

    // CAPTURE
    let mut child = spawn_suspended(&cmdline).expect("Could not spawn child process");

    let clk_post_child_spawn = get_epoch_ms();
    pin_process_to_cpu(child.id(), 0u16);

    let mut capture_session = CaptureSession::new(0).expect("Could not start capture session");
    capture_session.set_global_buffer_size(buffer_count, page_power).expect("Could not set global buffer sizes");
    println!("capture_session: {:?}", capture_session);
    capture_session.configure_tracing(child.id(), &[filter]).expect("Could not configure tracing!");

    capture_session.set_trace_enable(true, true).expect("Could not enable tracing!");

    let clk_pre_unsuspend = get_epoch_ms();
    unsuspend_process(child.id());

    let exit_status = child.wait().expect("Failed to wait for child pid!");
    let clk_post_child_exit = get_epoch_ms();
    println!("Child returned with status code {:?}", exit_status);
    capture_session.set_trace_enable(false, false).expect("Could not disable trace after child exited");

    let trace = capture_session.get_trace().expect("Could not retrieve trace!");
    println!("Got trace of length: {:?} {:?}", trace.len(), &trace[0..std::cmp::min(trace.len(), 100)]);
    let clk_post_get_trace = get_epoch_ms();
    // ANALYZE

    let mut cov = FullTrace64Bit::new(hive.uvip_slide());
    // let mut cov = BlockEdgeSetCoverageInfo::new(hive.uvip_slide());
    let mut analysis_session = AnalysisSession::new(hive).expect("Could not create analysis session!");
    analysis_session.reconfigure_with_terminated_trace_buffer(
        trace,
        filter.start.try_into().unwrap()
    ).expect("Failed to reconfigure analysis session");

    let clk_post_configure_with_terminated_buffer = get_epoch_ms();

    analysis_session.decode_with_callback(|block| {
        cov.record_block(block.try_into().unwrap())
    }).expect("Could not decode trace");

    let clk_post_decode = get_epoch_ms();
    let (nvals, nbytes) = cov.report_sizes();
    // let edges = cov.bbs.into_iter().unique().collect::<Vec<_>>();
    let clk_post_unique = get_epoch_ms();

    let timestamps = [clk_pre_all, clk_post_hive_load, clk_post_child_spawn, clk_pre_unsuspend, clk_post_child_exit, clk_post_get_trace, clk_post_configure_with_terminated_buffer, clk_post_decode, clk_post_unique];
    // let timestamps = timestamps[1..].iter()
    //     .map(|curr| curr - timestamps[0])
    //     .collect::<Vec<_>>();
    println!("timestamps: {:?}", timestamps);
    let total_time = timestamps[timestamps.len() - 1] - timestamps[0];
    let child_time = timestamps[4] - timestamps[3];
    let decode_time = timestamps[7] - timestamps[6];
    let timestamps = timestamps[..timestamps.len()-1].iter()
        .zip(timestamps[1..].iter())
        .map(|(prev, curr)| curr - prev)
        .zip(&["load hive", "spawn child", "cpu pinned", "child_execution", "get_trace", "configure with buffer", "decode", "unique"])
        .collect::<Vec<_>>();
    println!("timestamps: {:?}", timestamps);

    let percent_slower = ((total_time as f64) / child_time as f64) * 100f64;
    let percent_slower_string = format!("{:.2}", percent_slower);

    println!("total time taken: {:?}", timestamps.iter().map(|(x, _)| *x).collect::<Vec<u128>>().into_iter().sum::<u128>());
    println!("percent slowdown: {}", percent_slower_string);
    // println!("Trace length: {:?}", cov.bbs.len());
    println!("Data size of coverage stats: 0x{:x}", datasize::data_size(&cov));
    cov.print_result();

    let name = cov.name();
    let msg = format!("{name},{percent_slower_string},{child_time},{decode_time},{nvals},{nbytes}\n");
    append_to_file(&format!("stats_{}.csv", cmdline[0].split("/").last().unwrap()), &msg);
    // println!("Unique edges: {:?}", edges.len());
    // println!(
    //     "{}\n",
    //     cov.bbs.len(),
    // );
    // let blockreprs = cov.bbs.iter().map(|x| format!("0x{:x}", x)).collect::<Vec<_>>();
    // println!("{:?}", blockreprs);


    Ok(())
}