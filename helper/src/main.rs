/// One write per message, so lines do not interleave with nginx's.
macro_rules! log {
    ($($arg:tt)*) => {{
        use std::io::Write;
        let line = format!("sundew-helper: {}\n", format_args!($($arg)*));
        let _ = std::io::stderr().write_all(line.as_bytes());
    }};
}

mod engine;
mod keeper;
mod nl;
mod proto;
mod sys;

fn main() {
    let mut engine = false;
    let mut restarted = false;
    for a in std::env::args_os().skip(1) {
        match a.to_str() {
            Some("--engine") => engine = true,
            Some("--restarted") => restarted = true,
            _ => {
                log!("started by nginx; not meant to be run directly");
                std::process::exit(64);
            }
        }
    }
    if engine {
        engine::run(restarted)
    } else {
        keeper::run()
    }
}
