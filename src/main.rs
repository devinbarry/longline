mod ai_judge;
mod cli;
mod logger;
mod output;
mod parser;
mod policy;
mod types;

fn main() {
    std::process::exit(cli::run());
}
