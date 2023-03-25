# nagios_automation
Nagios automation via http requests to enable and disable checks and notifications, suitable for decommisioning of servers.

In some production environments it's not suitable to change config files and reboot the nagios monitoring service, so Nagstamon and HTTP requests are the other options I know.

Manual HTTP interactions get tiresome very quickly.
Automation is the answer.

- Checks for validity of SSH key in 'localhost'.  Can be changed in line 22.
- ./decom_nagios.tcl -h  for help page
- Can be used for one or more nagios servers in same command line
- Can be used to issue commands to one or more hosts being monitored by nagios
- Several commands can be used separately, like --dach - disable active checks for the host
- Or a meta-command like --decom-phase-1 can be used that sets some other commands for ease of use
- --decom-phase-1-undo, in case the actions should be reverted

