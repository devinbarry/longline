mod cli;
mod evaluator;
mod logger;
mod output;

fn main() {
    std::process::exit(cli::run());
}
