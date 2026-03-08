use clap::{Parser, Subcommand};
use lokalvault::{cli, daemon, run_cmd};
use std::io::Read;

#[derive(Parser)]
#[command(name = "lokalvault")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

impl Cli {
    #[cfg(test)]
    fn parse_from<I, T>(itr: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        <Self as clap::Parser>::try_parse_from(itr)
    }
}

#[derive(Subcommand)]
enum Commands {
    #[command(name = "daemon-poc")]
    DaemonPoc,
    #[command(name = "daemon")]
    Daemon,
    Create,
    Unlock,
    Lock,
    Init {
        project_name: Option<String>,
    },
    Add {
        #[arg(long)]
        project: Option<String>,
        key: String,
        value: Option<String>,
    },
    Update {
        #[arg(long)]
        project: Option<String>,
        key: String,
        value: Option<String>,
    },
    Delete {
        #[arg(long)]
        project: Option<String>,
        key: String,
    },
    DeleteProject {
        project: String,
    },
    List {
        project: Option<String>,
    },
    Get {
        project: Option<String>,
        key: String,
    },
    Import {
        path: String,
        #[arg(long)]
        project: String,
    },
    Export {
        project: Option<String>,
        #[arg(long)]
        format: String,
    },
    Status {},
    Push {
        project: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        env: Option<String>,
    },
    Run {
        #[arg(long)]
        project: Option<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::DaemonPoc => daemon::run_daemon_poc().await.map(|_| ()),
        Commands::Daemon => {
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            let (vault, _password): (lokalvault::vault_file::VaultData, String) =
                serde_json::from_slice(&input).unwrap();
            daemon::run_daemon_server(vault).await.map(|_| ())
        }
        Commands::Create => cli::cmd_create().map(|message| {
            eprintln!("{message}");
        }),
        Commands::Unlock => cli::cmd_unlock().map(|message| {
            eprintln!("{message}");
        }),
        Commands::Lock => cli::cmd_lock().map(|message| {
            eprintln!("{message}");
        }),
        Commands::Init { project_name } => cli::cmd_init(project_name.as_deref()).map(|message| {
            eprintln!("{message}");
        }),
        Commands::Add {
            project,
            key,
            value,
        } => cli::cmd_add(project.as_deref(), &key, value.as_deref()).map(|message| {
            eprintln!("{message}");
        }),
        Commands::Update {
            project,
            key,
            value,
        } => cli::cmd_update(project.as_deref(), &key, value.as_deref()).map(|message| {
            eprintln!("{message}");
        }),
        Commands::Delete { project, key } => {
            cli::cmd_delete(project.as_deref(), &key).map(|message| {
                eprintln!("{message}");
            })
        }
        Commands::DeleteProject { project } => cli::cmd_delete_project(&project).map(|message| {
            eprintln!("{message}");
        }),
        Commands::List { project } => cli::cmd_list(project.as_deref()).map(|output| {
            if !output.is_empty() {
                println!("{output}");
            }
        }),
        Commands::Get { project, key } => cli::cmd_get(project.as_deref(), &key).map(|value| {
            print!("{value}");
        }),
        Commands::Import { path, project } => {
            cli::cmd_import(std::path::Path::new(&path), &project).map(|message| {
                eprintln!("{message}");
            })
        }
        Commands::Export { project, format } => {
            let format = match cli::ExportFormat::parse(&format) {
                Ok(format) => format,
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            };
            cli::cmd_export(project.as_deref(), format).map(|output| {
                print!("{output}");
            })
        }
        Commands::Status {} => cli::cmd_status().map(|status| {
            println!("{status}");
        }),
        Commands::Push {
            project,
            target,
            env,
        } => {
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
            cli::cmd_push(&project, target, env.as_deref()).map(|message| {
                eprintln!("{message}");
            })
        }
        Commands::Run { project, command } => run_cmd::cmd_run_entry(project.as_deref(), command)
            .await
            .map(|_| ()),
    };

    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_update_command() {
        let cli = Cli::parse_from([
            "lokalvault",
            "update",
            "--project",
            "my-app",
            "OPENAI_KEY",
            "value",
        ])
        .unwrap();
        assert!(matches!(cli.command, Commands::Update { .. }));
    }

    #[test]
    fn test_parse_delete_command() {
        let cli =
            Cli::parse_from(["lokalvault", "delete", "--project", "my-app", "OPENAI_KEY"]).unwrap();
        assert!(matches!(cli.command, Commands::Delete { .. }));
    }

    #[test]
    fn test_parse_export_command() {
        let cli = Cli::parse_from(["lokalvault", "export", "my-app", "--format", "json"]).unwrap();
        assert!(matches!(cli.command, Commands::Export { .. }));
    }
}
