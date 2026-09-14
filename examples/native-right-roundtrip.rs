fn main() -> std::process::ExitCode {
    novaray_core::right_experiment::entry(std::env::args().skip(1).collect())
}
