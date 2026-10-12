# Open the appliance menu when the appliance administrator logs in interactively.
if [ "$(id -un 2>/dev/null)" = "nsadmin" ] && [ -t 0 ] && [ -z "${NS_CONSOLE:-}" ]; then
  export NS_CONSOLE=1
  sudo /opt/ns-appliance/bin/ns-console
  exit
fi
