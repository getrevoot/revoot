_revoot() {
  local current previous commands
  current="${COMP_WORDS[COMP_CWORD]}"
  previous="${COMP_WORDS[COMP_CWORD-1]}"
  commands="config init doctor review scan delegate rules mcp completions version help"
  case "$previous" in
    revoot) COMPREPLY=( $(compgen -W "$commands" -- "$current") ); return ;;
    completions) COMPREPLY=( $(compgen -W "bash zsh fish" -- "$current") ); return ;;
    --format) COMPREPLY=( $(compgen -W "human json sarif" -- "$current") ); return ;;
    --effort) COMPREPLY=( $(compgen -W "low medium high" -- "$current") ); return ;;
    --fork-behavior) COMPREPLY=( $(compgen -W "report-only skip trusted-target" -- "$current") ); return ;;
  esac
  case " ${COMP_WORDS[*]} " in
    *" review "*) COMPREPLY=( $(compgen -W "--base --ci --mr --pr --repo --preview --effort --max-parallel-groups --format --output --help" -- "$current") ) ;;
    *" scan "*) COMPREPLY=( $(compgen -W "--path --include-untracked --preview --format --help" -- "$current") ) ;;
    *" delegate "*) COMPREPLY=( $(compgen -W "preview rule --help" -- "$current") ) ;;
    *" rules "*) COMPREPLY=( $(compgen -W "check --json --help" -- "$current") ) ;;
    *" mcp "*) COMPREPLY=( $(compgen -W "serve" -- "$current") ) ;;
    *" doctor "*) COMPREPLY=( $(compgen -W "--json --help" -- "$current") ) ;;
    *" init gitlab "*) COMPREPLY=( $(compgen -W "--image --component --version --provider --model --fork-behavior --help" -- "$current") ) ;;
    *" init github "*) COMPREPLY=( $(compgen -W "--image --provider --model --fork-behavior --help" -- "$current") ) ;;
    *" init "*) COMPREPLY=( $(compgen -W "gitlab github" -- "$current") ) ;;
    *" config explain "*) COMPREPLY=( $(compgen -W "--json --base-config --config --context-lines --minimum-confidence --provider --model --max-files --max-input-bytes --max-findings --max-model-requests --deadline-seconds --publish --no-publish --help" -- "$current") ) ;;
  esac
}
complete -F _revoot revoot
