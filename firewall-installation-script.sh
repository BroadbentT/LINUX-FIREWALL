#!/bin/sh 
#**************************************************************************** #
#                                                                             #
#        Firewall implementation script for simple firewall policy            #
#       Release version 1.0 by Terence Broadbent BSc Cyber Security           #
#                                                                             # 
# *************************************************************************** # 
 
# *************************************************************************** # 
# AUTHOR  : Terence Broadbent                                                 # 
# CONTRACT: SME                                                               # 
# Version : 1.0                                                               # 
# Details : Define global variables used by this bash script.                 #
# Modified: N/A                                                               #
# *************************************************************************** # 
 
NET="ens33" # IMPORTANT!! CHANGE THIS TO MATCH YOUR NETWORK
IFS=","     # Enables script to read data from text files separated by commas.
LOGFILE="./Log1.txt" # The default log filename. 
 
# *************************************************************************** #
# AUTHOR  : Terence Broadbent                                                 #
# CONTRACT: SME                                                               #
# Version : 1.0                                                               #
# Details : Create log system & check that this script has root privileges.   # 
# Modified: N/A                                                               # 
# *************************************************************************** # 
 
echolog() ( echo $1 echo $1 >> $LOGFILE ) 

if [ $USER != "root" ]
    then echolog "Please run this bash script as root..."
    exit 0
else
    echolog "\n\tLINUX FIREWALL INSTALLATION LOG - VERSION 1.0\n" 
fi 
 
# *************************************************************************** # 
# AUTHOR  : Terence Broadbent                                                 #
# CONTRACT: SME                                                               #
# Version : 1.0                                                               # 
# Details : Ensure current firewall configuration is backed up & wiped clean. # 
# Modified: N/A                                                               #
# *************************************************************************** # 
 
echolog "[1]. Starting the firewall installation...\n" 
iptables-save -c > "./Iptables-old.txt" 2>&1 | tee -a $LOGFILE 
echolog "\t - Your current settings have been saved to ./Iptables-old.txt\n" 
echolog "[2]. Cleaning up any existing firewall protocols...\n" 
echolog "\t + Stopping iptables services." ufw disable 2>&1 | tee -a $LOGFILE
echolog "\t + Cleaning iptables." iptables -F 2>&1 | tee -a $LOGFILE 
iptables -t nat -F 2>&1 | tee -a $LOGFILE 
iptables -t mangle -F 2>&1 | tee -a $LOGFILE 
iptables -X 2>&1 | tee -a $LOGFILE 
echolog "\t + Iptables cleaned and wiped." 
echolog "\t + Restarting services." ufw enable 2>&1 | tee -a $LOGFILE 
echolog "\t - Cleaning of iptables completed.\n" 
 
# *************************************************************************** # 
# AUTHOR  : Terence Broadbent                                                 # 
# CONTRACT: SME                                                               # 
# Version : 1.0                                                               # 
# Details : Accept traffic through loopback 'lo' interface on the network.    # 
# Modified: N/A                                                               # 
# *************************************************************************** # 
 
echolog "[3]. Setting up a loopback on the firewall...\n" 
echolog "\t + Allowed: Loopback services." 
iptables -A INPUT -i lo -j ACCEPT 2>&1 | tee -a $LOGFILE 
iptables -A OUTPUT -o lo -j ACCEPT 2>&1 | tee -a $LOGFILE 
echolog "\t - Provision of loopback completed.\n"  

# *************************************************************************** # 
# AUTHOR  : Terence Broadbent                                                 # 
# CONTRACT: SME                                                               # 
# Version : 1.0                                                               # 
# Details : Protect the network from denial of service and pesky hackers.     # 
# Modified: N/A                                                               # 
# *************************************************************************** # 
 
echolog "[4]. Protecting the network from threat actors (Hackers!)...\n" 
echolog "\t + Blocking: Multicast IPs." 
iptables -A INPUT -m pkttype --pkt-type multicast -i $NET -j DROP 2>&1 | tee -a $LOGFILE 
iptables -A OUTPUT -m pkttype --pkt-type multicast -o $NET -j DROP 2>&1 | tee -a $LOGFILE

# ifconfig $NET -multicast 2>&1 | tee -a $LOGFILE --comment alternative option. 

echolog "\t + Blocking: Invalid packets." 
iptables -A INPUT -m state --state INVALID -j DROP 2>&1 | tee -a $LOGFILE
echolog "\t - Setting up syn attack configuration..." 
echolog "\t   [1] Limit SYN packets (recommended)?" 
echolog "\t   [2] Block all SYN packets?" 
while true;
     do read -p "Option:" CONT 
     if [ "$CONT" = "1" ];
         then echo Option:$CONT >> $LOGFILE
         echolog  "\t + Limiting: SYN flooding attack."
         iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j RETURN
         break 
    elif
        [ "$CONT" = "2" ]; 
        then echo Option:$CONT >> $LOGFILE
        echolog  "\t +    Blocking: SYN flooding attack."   
        iptables -A INPUT -p tcp --syn -j DROP 2>&1 | tee -a $LOGFILE
        break
   else
       printf "Error please re-select "
   fi
done 
echolog "\t + Blocking: Malformed packets." 
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP 2>&1 | tee -a $LOGFILE 
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP 2>&1 | tee -a $LOGFILE 
iptables -A INPUT -p tcp --tcp-flags SYN,ACK NONE -j DROP 2>&1 | tee -a $LOGFILE 
iptables -A INPUT -p tcp --tcp-flags RST,FIN RST,FIN -j DROP 2>&1 | tee -a $LOGFILE 
iptables -A INPUT -p tcp --tcp-flags SYN,URG SYN,URG -j DROP 2>&1 | tee -a $LOGFILE 
iptables -A INPUT -p tcp --tcp-flags ALL SYN,PSH -j DROP 2>&1 | tee -a $LOGFILE
iptables -A INPUT -p tcp --tcp-flags ALL SYN,ACK,PSH -j DROP 2>&1 | tee -a $LOGFILE 
echolog "\t + Blocking: Malformed syn packets." 
iptables -A INPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP 2>&1 | tee -a $LOGFILE 
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP 2>&1 | tee -a $LOGFILE 
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 2>&1 | tee -a $LOGFILE 
echolog "\t + Blocking: Null packets." 
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP 2>&1 | tee -a $LOGFILE 
echolog  "\t + Blocking: Xmas tree attack." 
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP 2>&1 | tee -a $LOGFILE
echolog "\t - Setting up smurf attack configuration..." 
echolog "\t   [1] Limit ICMP packets (recommended)?" 
echolog "\t   [2] Block all ICMP packets?"
while true; 
    do read -p "Option:" CONT 
     if [ "$CONT" = "1" ]; 
         then echo Option:$CONT >> $LOGFILE
         echolog  "\t + Limiting: Smurf attack."
         iptables -A INPUT -p icmp -m limit --limit 2/second --limit-burst 2 -j ACCEPT 2>&1 | tee -a $LOGFILE
        break
    elif 
        [ "$CONT" = "2" ]; 
        then echo Option:$CONT >> $LOGFILE
        echolog  "\t + Blocking: Smurf attack."
        iptables -A INPUT -p icmp --icmp-type any -j DROP 2>&1 | tee -a $LOGFILE
        break
    else
        printf "Error please re-select "   
  fi
done 
echolog  "\t + Blocking: Land attack." iptables -A INPUT -s 127.0.0.1/32 -j DROP 2>&1 | tee -a $LOGFILE 
echolog  "\t + Blocking: Teardrop attack." 
iptables -A INPUT -f -j DROP 2>&1 | tee -a $LOGFILE
echolog  "\t + Blocking: Invalid packets from leaving the network." 
iptables -A OUTPUT -m state --state INVALID -j DROP 2>&1 | tee -a $LOGFILE
iptables -A OUTPUT -p icmp -j DROP 2>&1 | tee -a $LOGFILE
iptables -A OUTPUT -p tcp --tcp-flags ALL ALL -j DROP 2>&1 | tee -a $LOGFILE
iptables -A OUTPUT -p tcp --tcp-flags ALL NONE -j DROP 2>&1 | tee -a $LOGFILE
iptables -A OUTPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP 2>&1 | tee -a $LOGFILE
iptables -A OUTPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP 2>&1 | tee -a $LOGFILE 
iptables -A OUTPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 2>&1 | tee -a $LOGFILE 
iptables -A OUTPUT -f -j DROP 2>&1 | tee -a $LOGFILE 
echolog "\t - Protection of the network completed.\n" 
 
# *************************************************************************** # 
# AUTHOR  : Terence Broadbent                                                 #
# CONTRACT: SME                                                               # 
# Version : 1.0                                                               # 
# Details : Open a IP black list file and reject them from the network.       # 
# TechNote: Best practice is to DROP however - specification states REJECT.   # 
# Modified: N/A                                                               # 
# *************************************************************************** # 
 
echolog "[5]. Loading the IP black list into the firewall...\n"
echolog "\t + Checking list exists." 
test -e "IP black list.txt" 2>&1 | tee -a $LOGFILE
ReturnValue=$? 
     if [ $ReturnValue = "1" ] 
     then   echolog "\t + Warning! - the required file 'IP black list.txt' is missing...\n"
     exit 1
else
     echolog "\t + List found,all good." 
fi
while read ip1 do
     echolog "\t + Rejecting: $ip1"
     iptables -A INPUT -s $ip1 -j REJECT 2>&1 | tee -a $LOGFILE 
done < "IP black list.txt" 
echolog "\t - Blacklisting IP addresses completed.\n" 
 
# *************************************************************************** # 
# AUTHOR  : Terence Broadbent                                                 # 
# CONTRACT: SME                                                               # 
# Version : 1.0                                                               # 
# Details : Open list file of protocols and ports to reject from the network. # 
# TechNote: Best practice is to DROP however -specification states REJECT.    # 
# Modified: N/A                                                               # 
# *************************************************************************** # 
 
echolog "[6]. Loading the list of ports to block into the firewall...\n" 
echolog "\t + Checking list exists." test -e "Banned ports list.txt" 2>&1 | tee -a $LOGFILE 
ReturnValue=$? 
      if [ $ReturnValue = "1" ] 
      then echolog "\t + Warning! the required file 'Blocked ports list.txt' is missing...\n"
      exit 1
else
      echolog "\t + List found,all good." 
fi
while read type2 pr2 p2 do
      echolog "\t + Rejecting: $type2 on port $p2 [$pr2]"   
      iptables -A $type2 -p $pr2 --destination-port $p2 -j REJECT 2>&1 | tee -a $LOGFILE
done < "Banned ports list.txt" 
echolog "\t - Port blocking completed.\n" 
 
# *************************************************************************** # 
# AUTHOR  : Terence Broadbent                                                 # 
# CONTRACT: SME                                                               #
# Version : 1.0                                                               # 
# Details : Open a simple list of banned websites to block from the network.  # 
# TechNote:  Upgrade to transparent HTTP proxy utilising squid in the future!!# 
# Modified: N/A                                                               # 
# *************************************************************************** # 
 
echolog "[7]. Loading the list of banned websites into the firewall...\n" 
echolog "\t + Checking list exists." test -e "Banned websites list.txt" 2>&1 | tee -a $LOGFILE 
ReturnValue=$? 
     if [ $ReturnValue = "1" ] 
     then   echolog "\t - Warning! the required file 'Banned websites list.txt' is missing..."
     exit 1
else
     echolog "\t + List found,all good."
fi
while read url3 do
     echolog "\t + Blocking: $url3"
     iptables -A OUTPUT -p tcp -m string --string $url3 --algo kmp -j DROP 2>&1 | tee -a $LOGFILE
done < "Banned websites list.txt" 
echolog "\t - Banning websites completed.\n" 
 
# *************************************************************************** # 
# AUTHOR  : Terence Broadbent                                                 # 
# CONTRACT: SME                                                               # 
# Version : 1.0                                                               # 
# Details : Open a IP white list file and allow them on the network.          # 
# Modified: N/A                                                               # 
# *************************************************************************** # 
 
echolog "[8]. Loading the IP white list into the firewall.\n" 
echolog "\t + Checking list exists." 
test -e "IP white list.txt" 2>&1 | tee -a $LOGFILE
ReturnValue=$? 
     if [ $ReturnValue = "1" ] 
     then   echolog "\t - Warning! the required file 'IP white list.txt' is missing..."   
     exit 1
else
     echolog "\t + List found,all good." 
fi
while read ip4 p4 do
     echolog "\t + Allowing: $ip4 on port $p4"
     iptables -A INPUT -p tcp -s $ip4 --dport $p4 -j ACCEPT 2>&1 | tee -a $LOGFILE
     iptables -A OUTPUT -p tcp -d $ip4 --dport $p4 -j ACCEPT 2>&1 | tee -a $LOGFILE
done < "IP white list.txt" 
echolog "\t - White listing of IP addresses completed.\n" 
 
# *************************************************************************** # 
# AUTHOR  : Terence Broadbent                                                 # 
# CONTRACT: SME                                                               # 
# Version : 1.0                                                               # 
# Details : Finally block access to everyone else.                            # 
# Modified: N/A                                                               #
# ***************************************************************************# 
 
echolog "[9]. Blocking all other access to the network...\n" 
iptables -A INPUT -j DROP 2>&1 | tee -a $LOGFILE
echolog "\t + Blocking: All other access." 
echolog "\t - Blocking of all other access completed.\n" 
 
# *************************************************************************** # 
# AUTHOR  : Terence Broadbent                                                 # 
# CONTRACT: SME                                                               # 
# Version : 1.0                                                               # 
# Details : Creating a logging chain for all dropped packets.                 # 
# Modified: N/A                                                               # 
# *************************************************************************** # 
 
echolog "[10]. Finally - creating a logging chain for dropped packets...\n" 
iptables -N LOGGING 2>&1 | tee -a $LOGFILE 
iptables -A INPUT -j LOGGING 2>&1 | tee -a $LOGFILE
iptables -A OUTPUT -j LOGGING 2>&1 | tee -a $LOGFILE
iptables -A LOGGING -m limit --limit 2/min --limit-burst 3 -j LOG --log-prefix "IPTables-Dropped: " --log-level debug 2>&1 | tee -a $LOGFILE
iptables -A LOGGING -j DROP 2>&1 | tee -a $LOGFILE
echolog "\t + Logging chain IPTables-Dropped created." 
echolog "\t - logging all dropped packets completed.\n" 
 
# ************************************************************************** # 
# AUTHOR  : Terence Broadbent                                                #
# CONTRACT: SME                                                              # 
# Version : 1.0                                                              # 
# Details : Save configuration & display the final settings to the screen.   #
# Modified: N/A                                                              # 
# ************************************************************************** # 
 
echolog "[11]. Program completed sucessfully...\n" 
echolog "\t - Setting up save and exit configuration." 
echolog "\t   [1] Save and display this new configuration (recommended)?" 
echolog "\t   [2] Save but do not display this new configuration?" 
echolog "\t   [3] Exit without saving?"
while true; do
    read -p "Option:" CONT 
    if [ "$CONT" = "1" ]; 
        then echo Option:$CONT >> $LOGFILE
        iptables-save >> /dev/null
        echolog "\t - Configuration saved.\n"
        iptables -L INPUT --line-numbers 2>&1 | tee -a $LOGFILE
        iptables -L OUTPUT --line-numbers 2>&1 | tee -a $LOGFILE
        break
   elif
        [ "$CONT" = "2" ]; 
        then echo Option:$CONT >> $LOGFILE
        iptables-save > /dev/null   echolog "\t - Configuration saved.\n"   
        break
   elif
        [ "$CONT" = "3" ]; 
        then echo Option:$CONT >> $LOGFILE
        echolog "\t - Configuration not saved.\n"
        break
   else
        printf "Error please re-select "
   fi
done
echolog "\nFor any additional manual commands - all rules are kept in \etc\sysconfig\iptables.\n" 
#eof
