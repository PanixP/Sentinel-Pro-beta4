#!/bin/bash
set -euo pipefail

detect_sclibridge() {
  local candidates=(
    "/Users/Shared/Savant/Applications/RacePointMedia/sclibridge"
    "/Users/RPM/Applications/RacePointMedia/sclibridge"
    "/home/RPM/Applications/RacePointMedia/sclibridge"
    "/usr/local/bin/sclibridge"
  )
  local candidate
  for candidate in "${candidates[@]}"; do
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

say() {
  printf '%s\n' "$*"
}

main() {
  local scl
  scl="$(detect_sclibridge)" || {
    say "Unable to find sclibridge in any supported location."
    exit 1
  }

  say "Using sclibridge: ${scl}"

  "${scl}" removetrigger rbwd >/dev/null 2>&1 || true
  "${scl}" removetrigger rubi >/dev/null 2>&1 || true
  sleep 2
  pkill -f rubi >/dev/null 2>&1 || true

  local generic_zone
  generic_zone="$("${scl}" userzones | tr '\n' '\0' | xargs -0 -I{} "${scl}" servicesforzone "{}" 2>/dev/null | grep GENERIC | head -n 1 | tr '-' '\n' | head -n 1)"
  if [[ -z "${generic_zone}" ]]; then
    say "Unable to resolve a GENERIC service zone for rubi trigger install."
    exit 1
  fi

  "${scl}" settrigger rbwd 1 State global CurrentMinute Equal global.CurrentMinute 0 \
    "${generic_zone}" "" "" 1 "SVC_GEN_GENERIC" "RunCLIProgram" "COMMAND_STRING" \
    "lsof -i :25809 >/dev/null 2>&1 || ${scl} writestate global.rubi 1 global.rubi 0" >/dev/null

  "${scl}" settrigger rubi 1 String global rubi "Not Equal" 1 0 \
    "${generic_zone}" "" "" 1 "SVC_GEN_GENERIC" "RunCLIProgram" "COMMAND_STRING" \
    "nohup ruby -r socket -e 'fork do
        Process.setsid
        exit if fork
        STDIN.reopen(%(/dev/null))
        STDOUT.reopen(%(/dev/null), %(a))
        STDERR.reopen(%(/dev/null), %(a))
        fd_max = Process.getrlimit(:NOFILE)[0]
        3.upto(fd_max) do |i|
          begin
            IO.for_fd(i).close
          rescue Errno::EBADF, ArgumentError
          end
        end
        scb = %(#{scl})
        %x(#{scb} writestate global.rubi 1)
        Process.daemon
        Process.setproctitle(%(rubi))
        def handle_client(client)
          pid = fork { exec(%(irb -f --noecho --noprompt), in: client, out: client, err: client) }
          client.close
          Process.detach(pid) if pid
        end
        begin
          server = TCPServer.new(%(127.0.0.1), 25809)
          loop { handle_client(server.accept) }
        rescue => e
          safe_message = e.message.to_s.gsub(%( ), %(_))
          %x(#{scb} writestate global.rubierror #{safe_message})
        ensure
          server.close if defined?(server) && server
          %x(#{scb} writestate global.rubi 0)
        end
      end' &" >/dev/null

  "${scl}" writestate global.rubi 2 >/dev/null

  say "rubi startup triggers installed."
  say "Important: rubi-based profiles should use Address on Wire 127.0.0.1 and port 25809."
  say "Uninstall with: ${scl} removetrigger rubi && ${scl} removetrigger rbwd && sleep 5 && pkill -f rubi"
}

main "$@"
