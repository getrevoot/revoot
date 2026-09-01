#![forbid(unsafe_code)]

use std::{env, process};

use revoot::completion::{CompletionShell, render as render_completion};
use revoot::config;
use revoot::github_init::{GitHubInitOptions, render_github_actions};
use revoot::gitlab_init::{GitLabInitOptions, render_gitlab_ci};
use revoot::review_command;
use revoot_core::{DOCTOR_SCHEMA_VERSION, Diagnostic, ErrorCode};
use serde::Serialize;

#[derive(Debug, Default)]
enum ReportMode {
    #[default]
    Human,
    Json,
}

#[derive(Debug, Default)]
struct DoctorArgs {
    report: ReportMode,
    help: bool,
}

#[derive(Serialize)]
struct DoctorReport {
    schema_version: &'static str,
    revoot: RevootFacts,
    capabilities: CapabilityFacts,
}

#[derive(Serialize)]
struct RevootFacts {
    version: &'static str,
    target_os: &'static str,
    target_architecture: &'static str,
}

#[derive(Serialize)]
struct CapabilityFacts {
    architecture: &'static str,
    review_available: bool,
    provider_adapters: u8,
    publication_adapters: &'static [&'static str],
}

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(diagnostic) => {
            eprintln!("{}: {}", diagnostic.machine_code, diagnostic.message);
            if let Some(remediation) = diagnostic.remediation {
                eprintln!("remediation: {remediation}");
            }
            process::exit(2);
        }
    }
}

fn run() -> Result<i32, Diagnostic> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_help();
        return Ok(0);
    };

    match command.as_str() {
        "config" => config::run(args, env::vars_os()),
        "init" => run_init(args),
        "doctor" => run_doctor(&parse_doctor_args(args)?),
        "completions" => run_completions(args),
        "review" => review_command::run(
            args,
            env::vars_os(),
            &env::current_dir().map_err(|_| {
                Diagnostic::new(
                    ErrorCode::RepositoryUnavailable,
                    "current directory is unavailable",
                )
            })?,
        ),
        "mcp" => {
            let Some(subcommand) = args.next() else {
                return Err(Diagnostic::new(
                    ErrorCode::CliInvalidArgument,
                    "mcp requires the `serve` subcommand",
                ));
            };
            if subcommand != "serve" || args.next().is_some() {
                return Err(Diagnostic::new(
                    ErrorCode::CliInvalidArgument,
                    "usage: revoot mcp serve",
                ));
            }
            revoot::mcp_server::serve_stdio(&env::current_dir().map_err(|_| {
                Diagnostic::new(
                    ErrorCode::RepositoryUnavailable,
                    "current directory is unavailable",
                )
            })?)
            .map(|()| 0)
            .map_err(|message| Diagnostic::new(ErrorCode::ReviewFailed, message))
        }
        "version" | "--version" | "-V" => {
            println!("revoot {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "help" | "--help" | "-h" => {
            print_help();
            Ok(0)
        }
        _ => Err(Diagnostic::new(
            ErrorCode::CliInvalidArgument,
            format!("unknown command: {command}"),
        )),
    }
}

fn parse_doctor_args(args: impl Iterator<Item = String>) -> Result<DoctorArgs, Diagnostic> {
    let mut parsed = DoctorArgs::default();
    for argument in args {
        match argument.as_str() {
            "--json" => parsed.report = ReportMode::Json,
            "--help" | "-h" => {
                parsed.help = true;
                return Ok(parsed);
            }
            _ => {
                return Err(Diagnostic::new(
                    ErrorCode::CliInvalidArgument,
                    format!("unknown doctor option: {argument}"),
                ));
            }
        }
    }
    Ok(parsed)
}

fn run_init(mut args: impl Iterator<Item = String>) -> Result<i32, Diagnostic> {
    let Some(target) = args.next() else {
        return Err(Diagnostic::new(
            ErrorCode::CliInvalidArgument,
            "init requires the `gitlab` or `github` target",
        ));
    };
    if matches!(target.as_str(), "help" | "--help" | "-h") {
        print_init_help();
        return Ok(0);
    }
    if target == "github" {
        return run_init_github(args);
    }
    if target != "gitlab" {
        return Err(Diagnostic::new(
            ErrorCode::CliInvalidArgument,
            format!("unknown init target: {target}"),
        ));
    }
    let mut options = GitLabInitOptions::default();
    while let Some(argument) = args.next() {
        let value = match argument.as_str() {
            "--component" | "--version" | "--image" | "--provider" | "--model"
            | "--fork-behavior" => args.next().ok_or_else(|| {
                Diagnostic::new(
                    ErrorCode::CliInvalidArgument,
                    format!("{argument} requires a value"),
                )
            })?,
            "--help" | "-h" => {
                println!(
                    "USAGE:\n  revoot init gitlab --image IMAGE@sha256:DIGEST [--component PATH] [--version VERSION] [--provider NAME] [--model NAME] [--fork-behavior report-only|skip]"
                );
                return Ok(0);
            }
            _ => {
                return Err(Diagnostic::new(
                    ErrorCode::CliInvalidArgument,
                    format!("unknown init gitlab option: {argument}"),
                ));
            }
        };
        match argument.as_str() {
            "--component" => options.component = value,
            "--version" => options.version = value,
            "--image" => options.image = value,
            "--provider" => options.provider = value,
            "--model" => options.model = value,
            "--fork-behavior" => options.fork_behavior = value,
            _ => unreachable!(),
        }
    }
    let rendered = render_gitlab_ci(&options)
        .map_err(|error| Diagnostic::new(ErrorCode::ContractInvalid, error.to_string()))?;
    print!("{rendered}");
    Ok(0)
}

fn run_init_github(mut args: impl Iterator<Item = String>) -> Result<i32, Diagnostic> {
    let mut options = GitHubInitOptions::default();
    while let Some(argument) = args.next() {
        let value = match argument.as_str() {
            "--image" | "--provider" | "--model" | "--fork-behavior" => {
                args.next().ok_or_else(|| {
                    Diagnostic::new(
                        ErrorCode::CliInvalidArgument,
                        format!("{argument} requires a value"),
                    )
                })?
            }
            "--help" | "-h" => {
                println!(
                    "USAGE:\n  revoot init github --image IMAGE@sha256:DIGEST [--provider NAME] [--model NAME] [--fork-behavior skip|report-only]"
                );
                return Ok(0);
            }
            _ => {
                return Err(Diagnostic::new(
                    ErrorCode::CliInvalidArgument,
                    format!("unknown init github option: {argument}"),
                ));
            }
        };
        match argument.as_str() {
            "--image" => options.image = value,
            "--provider" => options.provider = value,
            "--model" => options.model = value,
            "--fork-behavior" => options.fork_behavior = value,
            _ => unreachable!(),
        }
    }
    let rendered = render_github_actions(&options)
        .map_err(|error| Diagnostic::new(ErrorCode::ContractInvalid, error.to_string()))?;
    print!("{rendered}");
    Ok(0)
}

fn run_completions(mut args: impl Iterator<Item = String>) -> Result<i32, Diagnostic> {
    let Some(shell) = args.next() else {
        return Err(Diagnostic::new(
            ErrorCode::CliInvalidArgument,
            "completions requires bash, zsh, or fish",
        ));
    };
    if matches!(shell.as_str(), "help" | "--help" | "-h") {
        print_completions_help();
        return Ok(0);
    }
    if args.next().is_some() {
        return Err(Diagnostic::new(
            ErrorCode::CliInvalidArgument,
            "completions accepts exactly one shell",
        ));
    }
    let shell = CompletionShell::try_from(shell.as_str())
        .map_err(|error| Diagnostic::new(ErrorCode::CliInvalidArgument, error.to_string()))?;
    print!("{}", render_completion(shell));
    Ok(0)
}

fn run_doctor(args: &DoctorArgs) -> Result<i32, Diagnostic> {
    if args.help {
        print_doctor_help();
        return Ok(0);
    }
    let report = DoctorReport {
        schema_version: DOCTOR_SCHEMA_VERSION,
        revoot: RevootFacts {
            version: env!("CARGO_PKG_VERSION"),
            target_os: env::consts::OS,
            target_architecture: env::consts::ARCH,
        },
        capabilities: CapabilityFacts {
            architecture: "in-process-rust-agent",
            review_available: true,
            provider_adapters: 2,
            publication_adapters: &["gitlab", "github"],
        },
    };

    match args.report {
        ReportMode::Human => {
            println!("Revoot {}", report.revoot.version);
            println!(
                "Host: {} / {}",
                report.revoot.target_os, report.revoot.target_architecture
            );
            println!("Architecture: {}", report.capabilities.architecture);
            println!(
                "Review CLI available: {}",
                report.capabilities.review_available
            );
        }
        ReportMode::Json => println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| Diagnostic::new(
                ErrorCode::ContractInvalid,
                format!("doctor report serialization failed: {error}"),
            ))?
        ),
    }
    Ok(0)
}

fn print_help() {
    println!(
        "revoot — independent review for agent-written code\n\nUSAGE:\n  revoot review [OPTIONS]\n  revoot mcp serve\n  revoot config explain [OPTIONS]\n  revoot init gitlab [OPTIONS]\n  revoot init github [OPTIONS]\n  revoot doctor [--json]\n  revoot completions bash|zsh|fish\n  revoot version"
    );
}

fn print_doctor_help() {
    println!("USAGE:\n  revoot doctor [--json]");
}

fn print_init_help() {
    println!("USAGE:\n  revoot init github [OPTIONS]\n  revoot init gitlab [OPTIONS]");
}

fn print_completions_help() {
    println!("USAGE:\n  revoot completions bash|zsh|fish");
}

#[cfg(test)]
mod tests {
    use super::parse_doctor_args;

    #[test]
    fn retired_runtime_options_are_rejected() {
        let result = parse_doctor_args(["--runtime".to_owned()].into_iter());
        assert!(result.is_err());
    }
}
