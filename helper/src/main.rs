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
                eprintln!("sundew-helper: started by nginx; not meant to be run directly");
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
