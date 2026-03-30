use clap::Parser;
use depot_cli::{Cli, RunError, run};
use depot_ui::{Audience, render_error};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", render_run_error(&error));
            ExitCode::FAILURE
        }
    }
}

fn render_run_error(error: &RunError) -> String {
    match error {
        RunError::App(depot_app::AppError::Depot(error)) => render_error(error, Audience::Client),
        _ => error.to_string(),
    }
}
