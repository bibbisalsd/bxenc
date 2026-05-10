mod args;
mod banner;
mod commands;
mod prompt;

use std::process::ExitCode;

use clap::Parser;

use args::Cli;

fn main() -> ExitCode {
    let cli = Cli::parse();

    if !cli.quiet && !cli.command.writes_stdout() {
        banner::print_startup();
    }

    match commands::run(&cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}
