complete -c revoot -f
complete -c revoot -n '__fish_use_subcommand' -a config -d 'Explain effective review configuration'
complete -c revoot -n '__fish_use_subcommand' -a init -d 'Generate integration configuration'
complete -c revoot -n '__fish_use_subcommand' -a doctor -d 'Report host and product readiness'
complete -c revoot -n '__fish_use_subcommand' -a review -d 'Review the current local change or a code-host change request'
complete -c revoot -n '__fish_use_subcommand' -a completions -d 'Generate shell completions'
complete -c revoot -n '__fish_use_subcommand' -a version -d 'Print the Revoot version'
complete -c revoot -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish'
complete -c revoot -n '__fish_seen_subcommand_from review' -l ci -d 'Use code-host CI context'
complete -c revoot -n '__fish_seen_subcommand_from review' -l base -r -d 'Local comparison base Git ref'
complete -c revoot -n '__fish_seen_subcommand_from review' -l mr -r -d 'Merge request IID'
complete -c revoot -n '__fish_seen_subcommand_from review' -l pr -r -d 'Pull request number'
complete -c revoot -n '__fish_seen_subcommand_from review' -l repo -r -d 'GitHub target owner/repository'
complete -c revoot -n '__fish_seen_subcommand_from review' -l format -r -a 'human json' -d 'Report format'
complete -c revoot -n '__fish_seen_subcommand_from review' -l output -r -F -d 'Write report'
complete -c revoot -n '__fish_seen_subcommand_from doctor' -l json -d 'Emit JSON'
complete -c revoot -n '__fish_seen_subcommand_from init' -a 'gitlab github'
complete -c revoot -n '__fish_seen_subcommand_from init' -l image -r
complete -c revoot -n '__fish_seen_subcommand_from init' -l component -r
complete -c revoot -n '__fish_seen_subcommand_from init' -l version -r
complete -c revoot -n '__fish_seen_subcommand_from init' -l provider -r
complete -c revoot -n '__fish_seen_subcommand_from init' -l model -r
complete -c revoot -n '__fish_seen_subcommand_from init' -l fork-behavior -r -a 'report-only skip trusted-target'
