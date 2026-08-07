#!/bin/bash
# User Script wrapper for sync-templates.py.
#
# WHY THIS EXISTS
#   The User Scripts plugin stores each script as a file literally named `script` and runs it
#   as SHELL. `sync-templates.py` is Python. Pasting the Python straight in as `script` gives a
#   file the plugin (and the Unraid agent's execute_user_script) tries to parse with bash, which
#   dies on the first Python line — bash exits 2 on a syntax error, with no useful stderr. The
#   editor also saves it mode 600, so the `#!/usr/bin/env python3` shebang cannot be honored
#   either: with no execute bit there is nothing to exec.
#
#   Naming the interpreter here makes the script work regardless of how the caller invokes it —
#   from the User Scripts UI, from the agent by name, or by hand.
#
# INSTALL (one time, on the Unraid host)
#   1. Create the User Script in the UI so the folder exists, named `sync_docker_templates`.
#   2. Put the Python beside it, keeping the .py name:
#        cp sync-templates.py /boot/config/plugins/user.scripts/scripts/sync_docker_templates/
#   3. Replace the script body with THIS file's contents (paste into the UI editor).
#
#   The agent can then run it by name: execute_user_script(script_name="sync_docker_templates",
#   confirm=true).
set -euo pipefail
exec python3 "$(dirname "$0")/sync-templates.py"
