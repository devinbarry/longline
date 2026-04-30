mod adapters;
mod cli;
mod evaluator;
mod logger;
mod output;
mod runtime;

fn main() {
    std::process::exit(cli::run());
}
