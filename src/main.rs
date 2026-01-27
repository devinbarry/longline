mod cli;
mod logger;
mod parser;
mod policy;
mod types;

fn main() {
    std::process::exit(cli::run());
}
