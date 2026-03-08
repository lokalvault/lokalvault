use clap::{Parser, Subcommand};
use lokalvault::{cli, daemon, run_cmd};

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
    Create,
    Unlock,
    Lock,
    Init {
        project_name: Option<String>,
    },
    Add {
        project: String,
        key: String,
        value: Option<String>,
    },
    List {
        project: Option<String>,
    },
    Get {
        project: String,
        key: String,
    },
    Import {
        path: String,
        #[arg(long)]
        project: String,
    },
    Status {},
    Push {
        project: String,
        #[arg(long)]
        target: String,
    },
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
        Commands::Create => cli::cmd_create().map(|message| {
            println!("{message}");
        }),
        Commands::Unlock => cli::cmd_unlock().map(|message| {
            println!("{message}");
        }),
        Commands::Lock => cli::cmd_lock().map(|message| {
            println!("{message}");
        }),
        Commands::Init { project_name } => cli::cmd_init(project_name.as_deref()).map(|message| {
            println!("{message}");
        }),
        Commands::Add {
            project,
            key,
            value,
        } => cli::cmd_add(&project, &key, value.as_deref()).map(|message| {
            println!("{message}");
        }),
        Commands::List { project } => cli::cmd_list(project.as_deref()).map(|output| {
            if !output.is_empty() {
                println!("{output}");
            }
        }),
        Commands::Get { project, key } => cli::cmd_get(&project, &key).map(|value| {
            print!("{value}");
        }),
        Commands::Import { path, project } => {
            cli::cmd_import(std::path::Path::new(&path), &project).map(|message| {
                println!("{message}");
            })
        }
        Commands::Status {} => cli::cmd_status().map(|status| {
            println!("{status}");
        }),
        Commands::Push { project, target } => {
            let target = match target.as_str() {
                "vercel" => cli::PushTarget::Vercel,
                "render" => cli::PushTarget::Render,
                "railway" => cli::PushTarget::Railway,
                "fly" => cli::PushTarget::Fly,
                "netlify" => cli::PushTarget::Netlify,
                _ => {
                    eprintln!("unsupported push target: {target}");
                    std::process::exit(1);
                }
            };
            cli::cmd_push(&project, target).map(|message| {
                println!("{message}");
            })
        }
        Commands::Run { command } => run_cmd::cmd_run_poc(command).await.map(|_| ()),
    };

    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
