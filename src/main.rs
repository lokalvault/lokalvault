use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{
    generate,
    shells::{Bash, Fish, Zsh},
};
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
        #[arg(long)]
        template: Option<String>,
    },
    Add {
        #[arg(long)]
        project: Option<String>,
        key: String,
        value: Option<String>,
        #[arg(long)]
        clipboard: bool,
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
    Diff {
        path: String,
        #[arg(long)]
        project: Option<String>,
    },
    Copy {
        project: Option<String>,
        key: String,
    },
    Shell {
        #[arg(long)]
        project: Option<String>,
    },
    Status {},
    Audit {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        method: Option<String>,
        #[arg(long)]
        process_name: Option<String>,
    },
    AuditClear,
    Doctor,
    Dev,
    AiSafe {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        generate_example: bool,
    },
    Share {
        project: String,
        #[arg(long)]
        output: Option<String>,
    },
    Claim {
        file: String,
        #[arg(long)]
        project: Option<String>,
    },
    ProtectRepo {
        #[arg(long)]
        project: Option<String>,
    },
    ScanDiff {
        #[arg(long)]
        project: Option<String>,
    },
    Completion {
        shell: String,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
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
        #[arg(long)]
        watch: bool,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    Get { key: String },
    Set { key: String, value: String },
    List,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::DaemonPoc => daemon::run_daemon_poc().await.map(|_| ()),
        Commands::Daemon => {
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            let (vault, password): (lokalvault::vault_file::VaultData, String) =
                serde_json::from_slice(&input).unwrap();
            daemon::run_daemon_server(vault, password).await.map(|_| ())
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
        Commands::Init {
            project_name,
            template,
        } => {
            let template = match template.as_deref() {
                Some(value) => match cli::ProjectTemplate::parse(value) {
                    Ok(template) => Some(template),
                    Err(error) => {
                        eprintln!("{error}");
                        std::process::exit(1);
                    }
                },
                None => None,
            };
            cli::cmd_init(project_name.as_deref(), template).map(|message| {
                eprintln!("{message}");
            })
        }
        Commands::Add {
            project,
            key,
            value,
            clipboard,
        } => cli::cmd_add(project.as_deref(), &key, value.as_deref(), clipboard).map(|message| {
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
        Commands::Diff { path, project } => {
            cli::cmd_diff(std::path::Path::new(&path), project.as_deref()).map(|output| {
                if !output.is_empty() {
                    println!("{output}");
                }
            })
        }
        Commands::Copy { project, key } => cli::cmd_copy(project.as_deref(), &key).map(|message| {
            eprintln!("{message}");
        }),
        Commands::Shell { project } => cli::cmd_shell(project.as_deref()).map(|message| {
            eprintln!("{message}");
        }),
        Commands::Status {} => cli::cmd_status().map(|status| {
            println!("{status}");
        }),
        Commands::Audit {
            project,
            since,
            method,
            process_name,
        } => {
            let since = match since.as_deref() {
                Some(value) => match parse_since_flag(value) {
                    Ok(since) => Some(since),
                    Err(error) => {
                        eprintln!("{error}");
                        std::process::exit(1);
                    }
                },
                None => None,
            };
            cli::cmd_audit(Some(lokalvault::audit_log::AuditFilter {
                project,
                since,
                method,
                process_name,
            }))
            .map(|output| {
                if !output.is_empty() {
                    println!("{output}");
                }
            })
        }
        Commands::AuditClear => cli::cmd_audit_clear().map(|message| {
            eprintln!("{message}");
        }),
        Commands::Doctor => cli::cmd_doctor().map(|(output, failed)| {
            println!("{output}");
            if failed {
                std::process::exit(1);
            }
        }),
        Commands::Dev => match cli::cmd_dev() {
            Ok(detected) => {
                let parts: Vec<String> = detected.split_whitespace().map(String::from).collect();
                match run_cmd::cmd_run_entry(None, parts, false).await {
                    Ok(status) => std::process::exit(status.code().unwrap_or(1)),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        },
        Commands::AiSafe {
            project,
            generate_example,
        } => cli::cmd_ai_safe(project.as_deref(), generate_example).map(|message| {
            eprintln!("{message}");
        }),
        Commands::Share { project, output } => {
            cli::cmd_share(&project, output.as_deref()).map(|message| {
                eprintln!("{message}");
            })
        }
        Commands::Claim { file, project } => {
            cli::cmd_claim(std::path::Path::new(&file), project.as_deref()).map(|message| {
                eprintln!("{message}");
            })
        }
        Commands::ProtectRepo { project } => {
            cli::cmd_protect_repo(project.as_deref()).map(|message| {
                eprintln!("{message}");
            })
        }
        Commands::ScanDiff { project } => {
            let mut diff = String::new();
            if let Err(error) = std::io::stdin().read_to_string(&mut diff) {
                return eprintln!("{}", error);
            }
            cli::cmd_scan_diff(project.as_deref(), &diff).map(|message| {
                if !message.is_empty() {
                    println!("{message}");
                }
            })
        }
        Commands::Completion { shell } => {
            let mut cmd = Cli::command();
            match shell.as_str() {
                "bash" => generate(Bash, &mut cmd, "lokalvault", &mut std::io::stdout()),
                "zsh" => generate(Zsh, &mut cmd, "lokalvault", &mut std::io::stdout()),
                "fish" => generate(Fish, &mut cmd, "lokalvault", &mut std::io::stdout()),
                _ => {
                    eprintln!("unsupported shell: {shell}");
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        Commands::Config { command } => match command {
            ConfigCommands::Get { key } => cli::cmd_config_get(&key).map(|value| {
                println!("{value}");
            }),
            ConfigCommands::Set { key, value } => {
                cli::cmd_config_set(&key, &value).map(|message| {
                    eprintln!("{message}");
                })
            }
            ConfigCommands::List => cli::cmd_config_list().map(|output| {
                if !output.is_empty() {
                    println!("{output}");
                }
            }),
        },
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
        Commands::Run {
            project,
            watch,
            command,
        } => match run_cmd::cmd_run_entry(project.as_deref(), command, watch).await {
            Ok(status) => std::process::exit(status.code().unwrap_or(1)),
            Err(e) => Err(e),
        },
    };

    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn parse_since_flag(input: &str) -> Result<std::time::SystemTime, String> {
    let value = input.trim();
    if value.is_empty() {
        return Err("since cannot be empty".to_string());
    }
    let Some(days) = value.strip_suffix('d') else {
        return Err("since must use day suffix like 7d".to_string());
    };
    let days: u64 = days
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(days * 24 * 60 * 60))
        .ok_or_else(|| "invalid since range".to_string())
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
