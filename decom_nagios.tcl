#!/bin/sh
# the next line restarts using tclsh \
exec tclsh "$0" ${1+"$@"}

#
# The purpose of this script is to automate Nagios actions in the context of decom of servers.
# For a nagios server and a host, performs a HTTP GET request and parses the
# response to identify: 1- correct hostname (case, -adm?);
#                       2a- services in 'critical' state for decom purposes
#                       2b- services in 'ok' state for undo purposes

package require http
package require tls
package require base64
package require htmlparse
package require struct
package require Expect

set username ""

proc testPassword {p} {
    set remote "localhost"
    puts "User password will be tested to prevent that a wrong password causes a 30 minute ban."
    puts "SSH connections to default host: $remote will be stopped."
    puts "\t'n', 'N' or 'Ctrl+C' to abort"
    puts "\t'servername' (and correct interface) if you want another server to be used for the test."
    puts "\t<Enter> to continue\n"
    set timeout 20
    exec stty echo
    flush stdout
    gets stdin data
    switch $data {
        "n" - "N" { exit 20 }
    }
    if {[string length $data] < 10 && [string length $data] > 0} {
        puts stderr "$data seems too short for a hostname.  Exiting."
        exit 21
    } elseif {[regexp {[^0-9a-zA-Z-]+} $data]} {
        puts stderr "$data seems to have characters not suitable for a hostname.  Exiting."
        exit 22
    }
    if {[string length $data] != 0} { set remote $data }
    # If a ssh connection to $remote host is available, close it 
    catch {exec ssh -O exit $remote} err
    # Test if password is correct
    set env(TERM) dumb
    log_user 0
    spawn ssh -l $::username $remote
    sleep 1
    expect {
        timeout {updateDb $id "timeout connecting"; puts stderr "$remote timeout connecting";  exit 30}
        -re "Connection refused" { puts stderr "$remote ssh connection refused";  exit 31}
        -re "Connection closed"  { puts stderr "$remote ssh connection closed";  exit 32}
        -re "no address.*" { puts stderr "$remote ssh no address";  exit 33}
        "assword: " { send -- "$::password\r" }
    }
    expect {
        timeout { puts stderr "$remote timeout after sending password";  exit 34}
        -nocase "denied*" { puts stderr "$remote denied";  exit 35}
        -nocase "Authentication failed*" { puts "$remote authentication failed";  exit 36}
        "\@*${remote}*(~)$ " { send -- "exit\r" }
        "\@${remote} ~]$ " { send -- "exit\r" }
    }
    log_user 1
}

namespace eval nagios {
    variable log_dir "~/logs"
    variable log_file "decom_nagios.log"
    variable log_f [file join $log_dir $log_file]
    variable log 1
    variable dach 0
    variable dacs 0
    variable epch 0
    variable epcs 0
    variable sprh 0
    variable sprs 0
    variable dnsh 0
    variable dnth 0
    variable each 0
    variable eacs 0
    variable dpch 0
    variable dpcs 0
    variable ensh 0
    variable enth 0
    variable header1 ""
    variable servers ""
    variable url_cgi ""
    variable cmd_name ""
    variable cmd_typ ""
    variable hostnames [list]
    variable commands [list]
    variable fdl {}

    proc showHelp {} {
        variable log_f
        puts ""
        puts "DESCRIPTION"
        puts "$::argv0 script is used to automate web interactions with one or more nagios servers at a time, in the context of the decommissioning of servers."
        puts "The script can be invoked with commands individually or with a meta-command that takes priority and sets its relative individual commands."
        puts "Actions relative to decom will be operated in each host and its services when they are in CRITICAL state (red). Works for SYS_*, APP_* and DAT_* services.  Commands are not executed against SNMP traps."
        puts "FLAGS for current operations are:"
        puts "  --username or -u - OAD login username"
        puts "  --servers 'fqdn, hostnames or IPs of nagios servers' - ex: '--servers 10.60.20.11' or '--servers \"10.30.10.5,nagios.some.fqdn\"'"
        puts "  --decom-phase-1 - meta-command that is equivalent as setting up all the following commands/flags individually"
        puts "\t--dach - command to disable active checks of a host"
        puts "\t--dacs - command to disable active checks of all services of a host"
        puts "\t--epch - command to enable passive checks of a host"
        puts "\t--epcs - command to enable passive checks of all services of a host"
        puts "\t--sprh - command to submit passive check result for a host"
        puts "\t--sprs - command to submit passive check result for services"
        puts "\t--dnth - command to disable notifications for this host"
        puts "\t--dnsh - command to disable notifications for all services on a host"
        puts ""
        puts "  --decom-phase-1-undo - meta-command that is equivalent as setting up all the following commands/flags individually"
        puts "\t--each - command to enable active checks of a host"
        puts "\t--eacs - command to enable active checks of all services of a host"
        puts "\t--dpch - command to disable passive checks of a host"
        puts "\t--dpcs - command to disable passive checks of all services of a host"
        puts "\t--enth - command to enable notifications for this host"
        puts "\t--ensh - command to enable notifications all services on a host"
        puts "OPTIONAL FLAGS"
        puts "'-h' or '--help' to show this help"
        puts "'-L' or '--no-log' not to log output"
        puts ""
        puts "LOGGING"
        puts "By default, the output is logged to $log_f."
        puts ""
        puts "INVOCATION - The script should be invoked like:"
        puts "$::argv0 FLAGS \"hostname hostname\" - i.e., a space or comma delimited list. Short version of hostnames (cannot be FQDN)."
        puts ""
        puts "EXAMPLES"
        puts "Need to provide at least one host to the script."
        puts "Usage examples:"
        puts "\tPerform all 'Decom Phase 1' procedures for one host in two nagios servers, using comma as a delimiter, with log:"
        puts "\t\t$::argv0 --servers \"nagios.some.fqdn,nagios2.some.fqdn\" --decom-phase-1 \"prod_machine1\""
        puts "\tIn one nagios server, deactivate active checks both for host and all its services for two hosts, using space as a delimiter, no log."
        puts "\t\t$::argv0 --servers \"10.60.20.11\" --dach --dacs \"prod_machine2 prod_machine3\""
        puts ""
    }
    proc createLogDir {d} {
        if {! [file isdirectory $d]} {
            set op [catch {file mkdir $d} err]
            if {$op > 0} {
                puts stderr "Error: $err"
                puts stderr "Check the problem and execute  `mkdir $d`"
                exit 4
            }
        }
    }
    proc createLogFile {d f} {
        if {! [file exists [file join $d $f]]} {
            set op [catch {close [open [file join $d $f] w]} err] 
            if {$op == 1} {
                puts stderr "Error: Unable to create log file [file join $d $f] for writing: $err"
                exit 5
            }
        }
    }
    proc checkLogFile {d f} {
        if {! [file isdirectory $d]} {
            createLogDir $d
            puts "Log directory $d has been created."
        }
        createLogFile $d $f
        if {! [file writable [file join $d $f]] } {
            puts stderr "Error: Log file [file join $d $f] doesn't exist or is not readable."
            puts stderr "Error: Create [file join $d $f]."
            exit 3
        }
    }

    proc parseOptions {largs} {
        variable log
        variable dach
        variable dacs
        variable epch
        variable epcs
        variable sprh
        variable sprs
        variable dnsh
        variable dnth
        variable each
        variable eacs
        variable dpch
        variable dpcs
        variable ensh
        variable enth
        variable servers
        variable hostnames
        variable commands
        set decom_phase_1 0
        set decom_phase_1_undo 0
        for {set i 0} {$i < [llength $largs]} {incr i} {
            set arg_key [lindex $largs $i]
            switch -glob -- $arg_key \
                "-h" - "--help" {
                    showHelp
                    exit 0
                } "-L" - "--no-log" {
                    set log 0
                } "-u" - "--username" {
                    set u [lindex $::argv [incr i]]
                    set ::username [string trim [string tolower $u]]
                    incr i -1
                } "--dach" {
                    set dach 1
                } "--dacs" {
                    set dacs 1
                } "--epch" {
                    set epch 1
                } "--epcs" {
                    set epcs 1
                } "--sprh" {
                    set sprh 1
                } "--sprs" {
                    set sprs 1
                } "--dnsh" {
                    set dnsh 1
                } "--dnth" {
                    set dnth 1
                } "--decom-phase-1" {
                    set decom_phase_1 1
                    set dach 1
                    set dacs 1
                    set epch 1
                    set epcs 1
                    set sprh 1
                    set sprs 1
                    set dnsh 1
                    set dnth 1
                } "--each" {
                    set each 1
                } "--eacs" {
                    set eacs 1
                } "--dpch" {
                    set dpch 1
                } "--dpcs" {
                    set dpcs 1
                } "--ensh" {
                    set ensh 1
                } "--enth" {
                    set enth 1
                } "--decom-phase-1-undo" {
                    set decom_phase_1_undo 1
                    set each 1
                    set eacs 1
                    set dpch 1
                    set dpcs 1
                    set ensh 1
                    set enth 1
                } "--servers" {
                    set s_arg [lindex $::argv [incr i]]
                    set s0 [string trim [string tolower $s_arg]]
                    set s1 [string map {, " "} $s0]
                    set servers [split [regsub -all {\s+} $s1 { }]]
                    incr i -1
                } default  { 
                    if {[string match "-*" $arg_key]} {
                        puts stderr "ERROR - option '$arg_key' is not a valid option."
                        puts stderr "Invoke `$::argv0 -h` for help"
                        exit 7
                    } else {
                        set beg [string first = $arg_key]
                        incr beg
                        set h [string trim [string tolower [string range $arg_key $beg end]]]
                        set h1 [string map {, " "} $h]
                        set hostnames [split [regsub -all {\s+} $h1 { }]]
                    }
                }
        }
        if {$::username eq ""} {puts stderr "Error:  Required to provide a username."; exit 6}
        if {$decom_phase_1 && $decom_phase_1_undo} { puts stderr "Error: Antagonic meta-commands issued: --decom_phase_1 and --decom_phase_1_undo.  Exiting."; exit 40 }
        if {$dach && $each} { puts stderr "Error: Antagonic commands issued: --dach and --each.  Exiting."; exit 41 }
        if {$dacs && $eacs} { puts stderr "Error: Antagonic commands issued: --dacs and --eacs.  Exiting."; exit 42 }
        if {$epch && $dpch} { puts stderr "Error: Antagonic commands issued: --epch and --dpch.  Exiting."; exit 43 }
        if {$epcs && $dpcs} { puts stderr "Error: Antagonic commands issued: --epcs and --dpcs.  Exiting."; exit 44 }
        if {$dnsh && $ensh} { puts stderr "Error: Antagonic commands issued: --dnsh and --ensh.  Exiting."; exit 45 }
        if {$dnth && $enth} { puts stderr "Error: Antagonic commands issued: --dnth and --enth.  Exiting."; exit 46 }
        foreach c [list dach dacs epch epcs sprh sprs dnsh dnth each eacs dpch dpcs ensh enth] {
            if {[set $c] == 1} {lappend commands $c}
        }
    }
    proc getPassword {} {
        stty -echo
        send_user -- "Password for $::username:  "
        expect_user -re "(.*)\n"
        stty echo
        send_user "\nThanks\n"
        set ::password $expect_out(1,string)
    }
    # dach "disable_active_checks_host" 48
    # each "enable_active_checks_host" 47
    # epch "enable_passive_checks_host" 92
    # dpch "disable_passive_checks_host" 93
    # dnth "disable_notifications_this_host" 25
    # enth "enable_notifications_this_host" 24
    # sprh "submit_passive_check_result_host" 87
    # dnsh "disable_notifications_all_services_host" 29  
    # ensh "enable_notifications_all_services_host" 28
    # eacs "enable_active_checks_service" 5
    # dacs "disable_active_checks_service" 6
    # dpcs "disable_passive_checks_service" 40
    # epcs "enable_passive_checks_service" 39
    # sprs "submit_passive_check_result_service" 30
    proc setInitialDef {} {
        variable servers
        variable header1
        variable cmd_name
        variable cmd_typ
        ::http::register https 443 ::tls::socket
        ::http::config -accept "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        #::http::config -useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
        ::http::config -useragent "[file tail [info script]]"
        set auth "Basic [::base64::encode $::username:$::password]"
        set header1 [list Authorization $auth]
        set commands [list \
                "dach" "disable_active_checks_host" 48 \
                "each" "enable_active_checks_host" 47 \
                "epch" "enable_passive_checks_host" 92 \
                "dpch" "disable_passive_checks_host" 93 \
                "dnth" "disable_notifications_this_host" 25 \
                "enth" "enable_notifications_this_host" 24 \
                "sprh" "submit_passive_check_result_host" 87 \
                "dnsh" "disable_notifications_all_services_host" 29 \
                "ensh" "enable_notifications_all_services_host" 28 \
                "eacs" "enable_active_checks_service" 5 \
                "dacs" "disable_active_checks_service" 6 \
                "dpcs" "disable_passive_checks_service" 40 \
                "epcs" "enable_passive_checks_service" 39 \
                "sprs" "submit_passive_check_result_service" 30 \
         ]
         foreach {short long code} $commands {
            dict set cmd_name $short $long
            dict set cmd_typ $long $code
         }
    }
    proc sendHttpRequest {url} {
        variable header1
        #puts "sendHttpRequest:   url {$url}    headers {$header1}"
        if {[catch {::http::geturl ${url} -keepalive 0 -headers $header1 -timeout 15000 } token]} {
            puts stderr "Problem with network: $token"
            exit 10
        }
        if {[::http::ncode $token] != 200} {
            puts stderr "Problem with server, [::http::code $token] :: [::http::code $token]"
        }
        return [::http::ncode $token]
    }
    # target is either: host or some service
    proc printScreen {code server host target command} {
        set ret_str ""
        switch -exact -- $code {
            200 { set ret_str "Ok" }
            default { set ret_str "http error code $code"}
        }
        set t [clock format [clock seconds] -format "%Y-%m-%d %H:%M:%S"] 
        puts "$t [format "%-18s" $server] [format "%-18s" $host] [format "%-28s" $target] [format "%-40s" $command] [format "%20s" $ret_str]"
    }
    proc printLog {code server host target command} {
        variable fdl
        set ret_str ""
        switch -exact -- $code {
            200 { set ret_str "Ok" }
            default { set ret_str "http error code $code"}
        }
        set t [clock format [clock seconds] -format "%Y-%m-%d %H:%M:%S"] 
        puts $fdl "$t [format "%-18s" $server] [format "%-18s" $host] [format "%-28s" $target] [format "%-40s" $command] [format "%20s" $ret_str]"
    }
    # Order of commands:
    # 1st - host related
    # 2nd - services related (disable active, enable passive)
    # 3rd - submit passive check result
    proc sortCommands {} {
        variable commands
        set commands_ordered [list]
        # decom commands
        if {[lsearch -exact $commands "dach"] != -1} {lappend commands_ordered "dach"}
        if {[lsearch -exact $commands "dnth"] != -1} {lappend commands_ordered "dnth"}
        if {[lsearch -exact $commands "epch"] != -1} {lappend commands_ordered "epch"}
        if {[lsearch -exact $commands "sprh"] != -1} {lappend commands_ordered "sprh"}
        if {[lsearch -exact $commands "dnsh"] != -1} {lappend commands_ordered "dnsh"}
        if {[lsearch -exact $commands "dacs"] != -1} {lappend commands_ordered "dacs"}
        if {[lsearch -exact $commands "epcs"] != -1} {lappend commands_ordered "epcs"}
        if {[lsearch -exact $commands "sprs"] != -1} {lappend commands_ordered "sprs"}
        # undo commands
        if {[lsearch -exact $commands "each"] != -1} {lappend commands_ordered "each"}
        if {[lsearch -exact $commands "eacs"] != -1} {lappend commands_ordered "eacs"}
        if {[lsearch -exact $commands "dpch"] != -1} {lappend commands_ordered "dpch"}
        if {[lsearch -exact $commands "dpcs"] != -1} {lappend commands_ordered "dpcs"}
        if {[lsearch -exact $commands "ensh"] != -1} {lappend commands_ordered "ensh"}
        if {[lsearch -exact $commands "enth"] != -1} {lappend commands_ordered "enth"}
        return $commands_ordered
    }
    # catch {exec /bin/bash -c "/usr/bin/curl -H 'Authorization:Basic b.......i' --insecure -m 15000 -A 'tcl curl' -d 'host=prod_host-adm&cmd_typ=6&cmd_mod=2&com_author=username&service=SYS_NRPE_AUTH_CHECK&btnSubmit=Commit' -X POST  'https://10.60.20.11/nagios/cgi-bin/cmd.cgi'" 2>@ stderr} err
    proc performAction {server host services} {
        variable cmd_name
        variable cmd_typ
        variable url_cgi
        variable commands
        variable log
        if {! [llength $commands] || $server eq ""} { return }
        set commands_ordered [sortCommands]
        # build different urls whether it's for host, service or submit check result
        set url_rest ""
        foreach c $commands_ordered {
            set command [dict get $cmd_name $c]
            set c_t [dict get $cmd_typ $command]
            set ret 0
            set ret_str ""
            set ret_target ""
            switch -exact -- $c {
                "dach" - "epch" - "dnth" - "dnsh" - "each" - "dpch" - "enth" - "ensh" {
                    set url_rest  "?host=$host&cmd_typ=$c_t&cmd_mod=2&com_author=$::username&btnSubmit=Commit"
                    set ret [sendHttpRequest ${url_cgi}${url_rest}]
                    printScreen $ret $server $host Host $command
                    if {$log} {printLog $ret $server $host Host $command}
                }
                "dacs" - "epcs" - "eacs" - "dpcs" {
                    foreach serv $services {
                        set url_rest  "?host=$host&cmd_typ=$c_t&cmd_mod=2&com_author=$::username&service=$serv"
                        set ret [sendHttpRequest ${url_cgi}${url_rest}]
                        printScreen $ret $server $host $serv $command
                        if {$log} {printLog $ret $server $host $serv $command}
                    }
                }
                "sprh" {
                    # plugin_state OK: 0; WARNING: 1; UNKNOWN: 3; CRITICAL: 2
                    set url_rest "?host=$host&cmd_typ=$c_t&cmd_mod=2&com_author=$::username&plugin_output=DECOM&plugin_state=0"
                    set ret [sendHttpRequest ${url_cgi}${url_rest}]
                    printScreen $ret $server $host Host $command
                    if {$log} {printLog $ret $server $host Host $command}
                }
                "sprs" {
                    foreach serv $services {
                        set url_rest "?host=$host&cmd_typ=$c_t&cmd_mod=2&com_author=$::username&service=$serv&plugin_output=DECOM&plugin_state=0"
                        set ret [sendHttpRequest ${url_cgi}${url_rest}]
                        printScreen $ret $server $host $serv $command
                        if {$log} {printLog $ret $server $host $serv $command}
                    }
                }
            }
        }
    }
    proc setDefinitionsServer {server} {
        variable header1
        variable url_cgi
        set url "https://$server/nagios"
        set url_cgi "$url/cgi-bin/cmd.cgi"
    }
    # To get the correct hostname used by Nagios, it's necessary to use a standalone HTTP GET query
    # that doesn't filter by 'SYS_*' services or 'CRITICAL' state.
    # Otherwise, if all services are green already, the 'getServerHostServices' proc has no means to
    # find the correct hostname, which can be in upper case or with some suffix.
    proc getServerHostName {n_server n_host} {
        # https://10.60.20.11/nagios/cgi-bin/extinfo.cgi?type=1&host=prod_server-int
        variable header1
        set url "https://$n_server/nagios/cgi-bin/status.cgi"
        set op "?navbarsearch=1&host=${n_host}*&search=Search"
        set tok [http::geturl ${url}${op} -headers $header1]
        set data [::http::data $tok]
        # -------- check for Matching Services
        http::cleanup $tok
        set tree [struct::tree]
        htmlparse::2tree $data $tree
        set hostname ""
        set ret [list]
        set ret_servers [list]
        set nodes [$tree nodes]
        foreach n $nodes {
            if {[$tree keyexists $n data] && [string match {href='extinfo.cgi?type=1&host=*} [$tree get $n data]] && [string match {* title=*} [$tree get $n data]]} {
                set html_attr [$tree get $n data]
                set start [string first "host=" $html_attr]
                set apostrophe [string first {'} $html_attr $start+1]
                set hostname [string range $html_attr $start+5 $apostrophe-1]
            }
        }
        return $hostname
    }
    # Type decom? disable active checks and notifications and enable passive.  Type undo?  the opposite. 
    proc determineTypeAction {} {
        variable dach
        variable dacs
        variable epch
        variable epcs
        variable dnsh
        variable dnth
        if { $dach || $dacs || $epch || $epcs || $dnsh || $dnth} { return "decom" }
        return "undo"
    }
    # AlerteType  16 : Critical; 8 : Unknown; 4 : Warning; 2 : OK
    # For multiple choice: AlerteType=4&AlerteType=8&AlerteType=16&servicestatustypes=28
    # servicstatustypes = sum of values of AlerteType.
    #
    # When selected Warning, Unknown, Critical
    # https://10.60.20.11/nagios/cgi-bin/status.cgi?navbarsearch=1&host=prod_host*&servicefilter=SYS_*&AlerteType=4&AlerteType=8&AlerteType=16&servicestatustypes=28&search=Search
    #
    # Only Critical
    # https://10.60.20.11/nagios/cgi-bin/status.cgi?navbarsearch=1&host=prod_host*&servicefilter=SYS_*&AlerteType=16&servicestatustypes=16&search=Search
    proc getServerHostServices {n_server n_host type_action} {
        variable header1
        # Type action decom
        set alerte_type 16
        set serv_st_types 16
        if {$type_action eq "undo"} {
            set alerte_type 2
            set serv_st_types 2
        }
        set url "https://$n_server/nagios/cgi-bin/status.cgi"
        set op "?navbarsearch=1&host=${n_host}*&AlerteType=${alerte_type}&servicestatustypes=${serv_st_types}&search=Search"
        set tok [http::geturl ${url}${op} -headers $header1]
        #set tok [http::geturl "https://10.60.20.11/nagios/cgi-bin/status.cgi?navbarsearch=1&host=prod_host1*&servicefilter=SYS_*&search=Search" -headers $headerl]
        set data [::http::data $tok]
        # -------- check for Matching Services
        http::cleanup $tok
        set tree [struct::tree]
        htmlparse::2tree $data $tree
        set ret_servers [list]
        set nodes [$tree nodes]
        foreach n $nodes {
            if {[$tree keyexists $n type] && [$tree get $n type] eq "PCDATA" && [$tree keyexists $n data] && \
                    ([string match "SYS_*" [$tree get $n data]] || [string match "DAT_*" [$tree get $n data]] || [string match "APP_*" [$tree get $n data]]) && \
                    ! [string match "*TRAP*" [$tree get $n data]]} {
                lappend ret_servers [$tree get $n data]
            } 
        }
        return $ret_servers
    }
}
#-------------------------- main --------------------------#
if {[info script] == $::argv0} {
    if {$nagios::log == 1} {
        nagios::checkLogFile $nagios::log_dir $nagios::log_file
        set nagios::fdl [open $nagios::log_f a]
    }
    nagios::parseOptions $argv
    nagios::getPassword
    testPassword $::password
    nagios::setInitialDef
    # print title line
    puts "[format "%-19s" Time] [format "%-18s" Server] [format "%-18s" Host] [format "%-28s" Target] [format "%-40s" Command] [format "%20s" Result]"
    if {$nagios::log == 1} {
        puts $nagios::fdl "[format "%-18s" Time] [format "%-18s" Server] [format "%-18s" Host] [format "%-28s" Target] [format "%-40s" Command] [format "%20s" Result]"
    }
    foreach host $nagios::hostnames {
        foreach server $nagios::servers {
            #set services [nagios::getServices $server $host]
            set nagios_host [nagios::getServerHostName $server $host]
            if {$nagios_host eq ""} { continue }
            # Determine what type of action to perform: decom or undo?
            set type_action [nagios::determineTypeAction]
            set services [nagios::getServerHostServices $server $host $type_action]
            #puts "(( nagios server: $server  (( host: $nagios_host (( type_action: $type_action  ((  $services (( [llength $services]"
            nagios::setDefinitionsServer $server
            nagios::performAction $server $nagios_host $services
        }
    }
    if {$nagios::log == 1} {
        close $nagios::fdl
    }
}


