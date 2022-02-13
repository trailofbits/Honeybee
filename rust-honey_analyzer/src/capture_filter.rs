pub use rust_honey_analyzer_sys::ha_capture_session_range_filter as CaptureFilter;

fn parse_filter_address(s: &str) -> Result<u64, String> {
    parse_int::parse::<u64>(s)
        .map_err(|e| e.to_string())
}

pub fn parse_capture_filter(s: &str) -> Result<CaptureFilter, String> {
    let mut iter = s.split("-");
    match (iter.next(), iter.next(), iter.next(), iter.next()) {

        (Some(start), Some(end), None, None) => Ok(
            CaptureFilter {
                enabled: true as u8,
                start: parse_filter_address(start)?,
                stop: parse_filter_address(end)?
            }),

        (Some(enabled), Some(start), Some(end), None) => Ok(
            CaptureFilter{
                enabled: (enabled == "false") as u8,
                start: parse_filter_address(start)?,
                stop: parse_filter_address(end)?
            }),

        other => Err(
            format!(
                "Could not parse {:?} as a CaptureFilter: expected: {{start}}-{{end}}! Got {:?} after splitting",
                s, other
            )
        )
    }
}