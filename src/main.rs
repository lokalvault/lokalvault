use clap::{Parser, Subcommand};
use lokalvault::{daemon, run_cmd};

#[derive(Parser)]
#[command(name = "lokalvault")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(name = "daemon-poc")]
    DaemonPoc,
    Run {
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::DaemonPoc => daemon::run_daemon_poc().await.map(|_| ()),
        Commands::Run { command } => run_cmd::cmd_run_poc(command).await.map(|_| ()),
    };

    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
