mod cli;
mod logger;
mod parser;
mod policy;

fn main() {
    std::process::exit(cli::run());
}
