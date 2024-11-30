#compdef rr

_rr() {
  # allow overridding rr with another command (e.g. if multiple versions are installed)
  zstyle -s :completion${curcontext}options command rr
  : ${rr:=rr}

  _rr_subcommands() {
    $rr --list-commands | cut -s -d ' ' -f 3
  }
  _rr_traces() {
    $rr ls | grep -v '^cpu_lock$'
  }

  _arguments -C \
    '1:subcommand:($(_rr_subcommands))' \
    '*::arg:->args'

  case $state in
    args) ;;
    *) return;;
  esac

  # different subcommands can have different options. show the appropriate options for each.
  # this is not ideal; `reply=` forces zsh to rerun `rr help` each time you hit tab.
  # the alternative though is rewriting half the code in _arguments.
  zstyle -e ':completion:*:*:rr:*:options' command \
    'reply=( '${(q)service}' help ${words:#-*} )'

  case $line[1] in
    # complete a command, then delegate to that command's completion script
    # -A means "don't use _normal until we've completed a non-option"
    record) _arguments -A '-*' '1:command: _precommand' '*:: :_normal -p $service' --;;
    replay|rerun|ps|sources|traceinfo|pack|dump) _arguments '*:trace:($(_rr_traces))' --;;
    help) _arguments ':subcommand:($(_rr_subcommands))' --;;
    explicit-sources|filename) _gnu_generic;;
    *) _arguments --;
  esac
}
