mod cli;
mod logger;
mod output;

fn main() {
    std::process::exit(cli::run());
}
