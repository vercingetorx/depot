use clap::Parser;
use depot_cli::{Cli, RunError, run};
use depot_ui::{
    Audience, ClientConsole, render_error, render_handshake_error, render_transport_error,
};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let rendered = render_run_error(&error);
            if !rendered.is_empty() {
                let _ = ClientConsole::new().print_error_line(&rendered);
            }
            ExitCode::FAILURE
        }
    }
}

fn render_run_error(error: &RunError) -> String {
    match error {
        RunError::BatchFailed(_) => String::new(),
        RunError::App(depot_app::AppError::Depot(error)) => render_error(error, Audience::Client),
        RunError::App(depot_app::AppError::Handshake(error)) => {
            render_handshake_error(error, Audience::Client)
        }
        RunError::App(depot_app::AppError::Transport(error)) => {
            render_transport_error(error, Audience::Client)
        }
        _ => error.to_string(),
    }
}
