complete -c revoot -f
complete -c revoot -n '__fish_use_subcommand' -a config -d 'Explain effective review configuration'
complete -c revoot -n '__fish_use_subcommand' -a init -d 'Generate integration configuration'
complete -c revoot -n '__fish_use_subcommand' -a doctor -d 'Report host and product readiness'
complete -c revoot -n '__fish_use_subcommand' -a review -d 'Review the current local change or a code-host change request'
complete -c revoot -n '__fish_use_subcommand' -a scan -d 'Prepare or run a bounded local source scan'
complete -c revoot -n '__fish_use_subcommand' -a delegate -d 'Emit provider-free delegation metadata'
complete -c revoot -n '__fish_use_subcommand' -a rules -d 'Inspect effective rule precedence'
complete -c revoot -n '__fish_use_subcommand' -a mcp -d 'Run the read-only stdio MCP server'
complete -c revoot -n '__fish_use_subcommand' -a completions -d 'Generate shell completions'
complete -c revoot -n '__fish_use_subcommand' -a version -d 'Print the Revoot version'
complete -c revoot -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish'
complete -c revoot -n '__fish_seen_subcommand_from review' -l ci -d 'Use code-host CI context'
complete -c revoot -n '__fish_seen_subcommand_from review' -l base -r -d 'Local comparison base Git ref'
complete -c revoot -n '__fish_seen_subcommand_from review' -l mr -r -d 'Merge request IID'
complete -c revoot -n '__fish_seen_subcommand_from review' -l pr -r -d 'Pull request number'
complete -c revoot -n '__fish_seen_subcommand_from review' -l repo -r -d 'GitHub target owner/repository'
complete -c revoot -n '__fish_seen_subcommand_from review' -l preview -d 'Show provider-free preparation'
complete -c revoot -n '__fish_seen_subcommand_from review' -l effort -r -a 'low medium high' -d 'Review effort'
complete -c revoot -n '__fish_seen_subcommand_from review' -l max-parallel-groups -r -a '1 2 3 4 5 6 7 8' -d 'Concurrent review groups'
complete -c revoot -n '__fish_seen_subcommand_from review' -l format -r -a 'human json sarif' -d 'Report format'
complete -c revoot -n '__fish_seen_subcommand_from review' -l output -r -F -d 'Write report'
complete -c revoot -n '__fish_seen_subcommand_from scan' -l path -r -F -d 'Limit scan to path'
complete -c revoot -n '__fish_seen_subcommand_from scan' -l include-untracked -d 'Include local untracked files'
complete -c revoot -n '__fish_seen_subcommand_from scan' -l preview -d 'Show provider-free scan plan'
complete -c revoot -n '__fish_seen_subcommand_from scan' -l format -r -a 'human json sarif' -d 'Output format'
complete -c revoot -n '__fish_seen_subcommand_from delegate' -a 'preview rule'
complete -c revoot -n '__fish_seen_subcommand_from rules' -a check
complete -c revoot -n '__fish_seen_subcommand_from rules' -l json -d 'Emit JSON'
complete -c revoot -n '__fish_seen_subcommand_from mcp' -a serve
complete -c revoot -n '__fish_seen_subcommand_from doctor' -l json -d 'Emit JSON'
complete -c revoot -n '__fish_seen_subcommand_from init' -a 'gitlab github'
complete -c revoot -n '__fish_seen_subcommand_from init' -l image -r
complete -c revoot -n '__fish_seen_subcommand_from init' -l component -r
complete -c revoot -n '__fish_seen_subcommand_from init' -l version -r
complete -c revoot -n '__fish_seen_subcommand_from init' -l provider -r
complete -c revoot -n '__fish_seen_subcommand_from init' -l model -r
complete -c revoot -n '__fish_seen_subcommand_from init' -l fork-behavior -r -a 'report-only skip trusted-target'
