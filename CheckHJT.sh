#!/bin/bash

me=`basename "$0"`
usage="\n${me} - Checks HJT logs and outputs issues

  Usage: ${me} [-discord] [-h] [-r] [-u] url/detection 
    Providing standard text will run it through the detection process
  Arguments:
   -h, --help : Show this help page
   -r         : Rescan last log
   -discord         : Print with formatting for Discord instead of CLI
   Default: Print with formatting for CLI\n"
# Made by https://github.com/superpowers04
# This file is extremely unorganised
# I do not currently plan on making this file optimised or overhauling it
# This is specifically meant for SuperBot but it works in Command Line 

hjtlog="./lasthjtlog.html"

if [[ "$1" == "-discord" ]]; then
	RED=':exclamation:'
	BLUE=''
	YELLOW=':grey_exclamation: '
	GREEN=':white_check_mark:'
	NC=''
	bold='**'
	arg1="${2//[\"\'\!\$\~]/ }"
	argall="${@//[\"\'\!\$\~]/ }"
	htmlfile="file:/${PWD}/chkhjt.html" 
	loghtmllink="Unconfigured"
	runmode="discord/other"
else
	RED='\e[0;31;40m'
	BLUE='\e[0;34;40m'
	YELLOW='\e[0;33;40m'
	GREEN='\e[0;32;40m'
	NC='\e[0;37;40m'
	bold='\e[1;37;40m'
	arg1="${1//[\"\'\!\$\~]/ }"
	runmode="cli"
	htmlfile="./chkhjt.html" 
	loghtmllink="file:/${PWD}/chkhjt.html"
fi

logtype=""

function detect {
	cur="None"
	
	#Hijackthis
	if [[ "$logtype" == *"hjt"* || "$logtype" == "" ]]; then

		case "${1}" in
		#Misc
				"Time of this report:"*)
					cur="DXDiag"
					if [[ "${has}" != *" ${cur}"*   ]]; then
						printf "\n${RED}This is a DXDiag log, Switching to DXDiag Mode"
						logtype="dxdiag"
						has="${has} ${cur}"
					fi
					;;
				*"<title>Ubuntu Pastebin</title>"*)
					cur="Ubpastebin"
					if [[ "${has}" != *"Ubpastebin"* ]]; then
						has="${has} Ubpastebin"
					fi
				;;

				*"# Malwarebytes AdwCleaner"*)
					printf "\n${RED}This is a Malwarebytes AdwCleaner log\n"
					echo "Error: Trying to scan a malwarebytes log" >> hjtchecker.log
					exit
					;;
				*"---- Minecraft Crash Report ----"* | *"[main/INFO]"* | *"[Client thread/INFO]: Setting user:"* | *"Starting minecraft server version:"*)
					printf "\n${RED}This is a Minecraft log, Not a hjt log, please use checkmc.sh or instead!\n"
					echo "Error: Trying to scan a Minecraft log in HJT mode!" >> hjtchecker.log
					exit
					;;			
				*"Hijackthis alternative for Unix using bash"*)
					cur="hjtver"
					if [[ "${has}" != *"hjtver"* ]]; then
						printf "\n>>> ${YELLOW} Unix HiJackThis alternative detected, Detections for this are extremely experimental, Please do not rely only on this bot for information with these types of logs"
						logtype="hjt for unix"
						has="${has} hjtver"
					fi
					;;
				*"HiJackThis Fork by Alex Dragokas"*)
					cur="hjtver"
					if [[ "${has}" != *"hjtver"* ]]; then

						printf "\n>>> ${GREEN}Ran with Alex Dragokas' Hijackthis fork"
						logtype="hjt"
						has="${has} hjtver"
					fi
					;;

				*"Trend Micro HijackThis"*)
					cur="hjtver"
					if [[ "${has}" != *"hjtver"* ]]; then
						printf "\n${RED}Ran with Trend Micro HijackThis, This bot is incompatible with this, Please do not rely on this bot for information with these types of logs! Use https://github.com/dragokas/hijackthis/raw/devel/binary/HiJackThis.exe for complete compatiblity. If you cannot do this then use Absol or Butterfly."
						logtype="hjt"
						has="${has} hjtver"
					fi
					;;
				"Platform:"*)
					cur="platform"
					if [[ "${has}" != *" ${cur}"*   ]]; then
						mess="${mess}\n  ${NC}${bold}Running on ${1:11}${bold}"
						has="${has} ${cur}"
					fi
					;;
				# "Elevated:  Yes"*)
				# 	cur="Elevated"
				# 	if [[ "${has}" != *" ${cur}"*   ]]; then
				# 		mess="${mess}\n${GREEN}Run as administrator"
				# 		has="${has} ${cur}"
				# 	fi
				# 	;;			
				"Ran by:"*)
					cur="ranas"
					if [[ "${has}" != *" ${cur}"*   ]]; then
						mess="${mess}\n  ${NC}${bold}Ran by: ${1:7}${bold}"
						has="${has} ${cur}"
					fi
					;;

	#Checks to not false flag

				# *"O4 - HKCU..Run:"*)
				# 	cur="warning"
				# ;; #HKLM run
				*"C:WindowsSystem32SecurityHealthSystray.exe"* | *"IntelIntel(R) Management Engine Components"*);; #Windows*
				*"Trusted Zone: "*)
					cur="warning"
					mess="${mess}\n${YELLOW}Trusted zone: \"${1:13}\", most likely not harmful"
				;; #Trusted Zone					
				*"(file missing)"*)
					cur="warning"
				;; #File missing		
				*"O4 - HKCU*StartupApprovedRun:"*);; #
				*"networkmanager-openvpn"*);; # Unix

	# Checks for piracy
				*"KMSpico"*)
					cur="crackedwindows"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Using Cracked Windows Keygen(${1}),Removal recommended"
						has="${has} $cur"
					fi
					;;		
				*"Shiginima"* | *"TLauncher.jar"*)
					cur="crackedlauncher"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Using Cracked launcher(${1}),Removal recommended"
						has="${has} $cur"
					fi
					;;
				*"127.0.0.1*authserver.mojang.com"*)
					cur="hosts"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Hosts file modified to redirect authentication to localhost, Tag = \`>>t winhosts\` or \`>>t unixhosts\`"
						has="${has} $cur"
					fi
					;;
				*"authserver.mojang.com"*)
					cur="hosts"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Hosts file modified to redirect authentication, Tag = \`>>t winhosts\` or \`>>t unixhosts\`"
						has="${has} $cur"
					fi
					;;
				*"127.0.0.1*sessionserver.mojang.com"*)
					cur="hostssess"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Hosts file modified to redirect session authentication to localhost, Tag = \`>>t winhosts\` or \`>>t unixhosts\`"
						has="${has} $cur"
					fi
					;;
				*"sessionserver.mojang.com"*)
					cur="hostssess"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Hosts file modified to redirect session authentication, Tag = \`>>t winhosts\` or \`>>t unixhosts\`"
						has="${has} $cur"
					fi
					;;
				*"hosts:"*)
					cur="hostsother"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${Yellow}Hosts file has been modified, It could cause issues. Check the log for more info"
						has="${has} $cur"
					fi
				;;			
				*"easymc"*)
					cur="easymc"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has easymc, Illegal, Removal Recommended"
						has="${has} $cur"
					fi
					;;
				*"mcleaks"*)
					cur="mcleaks"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has MCleaks, Illegal, Removal Recommended"
						has="${has} $cur"
					fi
					;;
				*"altening"*)
					cur="altening"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has Altening, Illegal, Removal Recommended. Run \`>>t altening\` and \`>>t winhosts\` "
						has="${has} $cur"
					fi
					;;


		#Antiviruses
				*"rsService"*)
					cur="rsService"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has Reason Core Security, Fake AV, Bundled with downloads, Remove"
						has="${has} $cur"
					fi
					;;

				*"Segurazo"*)
					cur="Segurazo"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${bold}${RED}Has Segurazo, fake antivirus. Follow <https://forums.malwarebytes.com/topic/249582-removal-instructions-for-segurazo> ${bold}" 
						#; tput setab 0 
						has="${has} $cur"
					fi
					;;			
				*"Eset.exe"* | *"C:Program FilesESETESET"* | *"ESET SecurityecmdS.exe"*)
					cur="eset"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has ESet, Removal Recommended, Tag:\`>>t hjt.eset\`"
						has="${has} $cur"
					fi
					;;
				*"Norton"*)
					cur="norton"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has Norton Antivirus, Removal Recommended"
						has="${has} $cur"
					fi
					;;
				*"avg.exe"*)
					cur="avg"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has AVG Antivirus, Removal Recommended"
						has="${has} $cur"
					fi
					;;
				*"asc.exe"* | *"advanced system care"*)
					cur="asc"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has Advanced System Care, Bad/Problematic AV"
						has="${has} $cur"
					fi
					;;
				*"mfefire"* | *"mcagent"* | *"Intel Security"* | *"McAfee WebAdvisor"*)
					cur="mcafee"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has Mcafee, Known to cause logging in issues, download and run the MCPR Tool from: http://us.mcafee.com/apps/supporttools/mcpr/mcpr.asp"
						has="${has} $cur"
					fi
					;;
				*"covenanteyes"*)
					cur="CovenantEyes"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has CovenantEyes, \`>>tag hjt.covenanteyes\`"
						has="${has} $cur"
					fi
					;;
				*"bitdefender"*)
					cur="Bitdefender"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has Bitdefender, If you are using BitDefender and having problems logging into the game, downloading game files or joining LAN worlds, you will need to uninstall BitDefender by following the instructions here, https://www.bitdefender.com/consumer/support/answer/2791"
						has="${has} $cur"
					fi
					;;
				*"ByteFence"*)
					cur="ByteFence"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has ByteFence, ByteFence is known to cause issues with Minecraft's installing and updating process. You will need to uninstall ByteFence. Steps can be found in the mod notice here: https://bugs.mojang.com/browse/MCL-5546"
						has="${has} $cur"
					fi
					;;
				*"WRTray"* | *"Webroot"*)
					cur="webroot"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has Webroot, Can cause issues with joining lan, Open Webroot and disable the built in Firewall."
						has="${has} $cur"
					fi
					;;
				*"COMODO"*)
					cur="ByteFence"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has Comodo AV, can cause issues with new launcher. Temporarily disable if it does."
						has="${has} $cur"
					fi
					;;
				*"Ad Guardian"*)
					cur="adguard"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has Ad Guardian, can cause issues with logging in, Recommended to remove."
						has="${has} $cur"
					fi
					;;
				*"avira"*)
					cur="avira"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has Avira, tag: \`>>tag avira\`"
						has="${has} $cur"
					fi
					;;
				*"avast"* | *"AvastSvc"*)
					cur="avast"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has Avast, Can cause issues with Minecraft. Removal recommended"
						has="${has} $cur"
					fi
					;;
					

				*"GlassWire"*)
					cur="GlassWire"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has a GlassWire Firewall, Removal recommended"
						has="${has} $cur"
					fi
					;;
				*"ZAM.exe"*)
					cur="ZAM"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has ZemenaAniMalware, old versions cause launcher issues. Remove or get latest version"
						has="${has} $cur"
					fi
					;;	
				*"F-Secure"*)
					cur="F-Secure"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has F-Secure, remove or disable"
						has="${has} $cur"
					fi
					;;		
				*"IOBit"*)
					cur="IOBit"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has IOBit Software, Recommended to remove all IOBit software"
						has="${has} $cur"
					fi
					;;		
				*"Kaspersky"*)
					cur="kaspersky"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has kaspersky, Can cause login and multiplayer connectivity problems. tag:\`>>tag hjt.kaspersky\`"
						has="${has} $cur"
					fi
					;;	
				*"C:WINDOWSsystem32SecurityHealthService.exe"* | *"C:WindowsSystem32SecurityHealthHost.exe"*);;

				*"antivirus"* | *"antimalware"* | *"security"* | *"bullguard"* | *"Antivirus"* | *"Antimalware"* | *"Security"* | *"BullGuard"*)
					cur="antivirus"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has a unknown/unregistered antivirus, Removal recommended(Is most likely a false positive)\n ${1}"
						has="${has} generic$cur"
					fi
					;;

		#VPNS
				*"HotspotShield"* | *"Hotspot Shield9.6.3bincmw_srv.exe"*)
					cur="hotspotshield"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has a Hotspot Shield(VPN), Can crash the game and cause issues, Follow <https://support.hotspotshield.com/hc/en-us/articles/202627494-Uninstalling-from-Windows>"
						has="${has} ${cur}"
					fi
					;;
				*"brave.com"* | *"brave-browser"*)
					cur="brave-browser"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has Brave Browser, causes issues logging in and is shady, Removal recommended"
						has="${has} $cur"
					fi
					;;	
				*"anoninevpn"*)
					cur="AnonineVPN"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has AnonineVPN, may cause internet issues. Disable"
						has="${has} $cur"
					fi
					;;	
				*"SecureLine"* | *"TnglCtrl"* | *"TunnelBear"* | *"ZenMate"* | *"pia_manager"* | *"HideMy.name"* | *"vpn"* | *"CyberGhost"* | *"Avira.VpnService"* | *"hola_svc.exe"* | *"ovpnagent"* | *"hidemesvc"* | *"Windscribe"*)
					cur="genericvpn"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has a VPN, may cause internet issues. Disable or remove $1"
						has="${has} ${cur}"
					fi
					;;	
				*"hamachi"* | *"LogMeIn Hamachi Ui"*)
					cur="hamachi"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has HAMACHI, Can cause network issues and can cause issues with network drivers, Highly recommended to remove"
						has="${has} $cur"
					fi
					;;	
				*"RvRvpnGui"*)
					cur="RvRvpnGui"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has Radmin, Can cause network issues and can cause issues with network drivers, Highly recommended to disable/Remove"
						has="${has} $cur"
					fi
					;;	
				# *"Pservice"*)
				# 	cur="parsec"
				# 	if [[ "${has}" != *" ${cur}"*  ]]; then
				# 		mess="${mess}\n${RED}Has Radmin, Can cause network issues and can cause issues with network drivers, Highly recommended to disable/Remove"
				# 		has="${has} $cur"
				# 	fi
				# 	;;	


		#Other
				*"HasteHaste.exe"* ) 
					cur="suspicious"
					mess="${mess}\n${bold}${YELLOW}Has suspicious software, '$1' Unknown if it can have an effect with minecraft, recommended to remove"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						has="${has} $cur"
					fi
				;;
				*"RestoroProtection"* | *"ZaxarLoader.exe"* | *"ipts.exe"* | *"ciff-3.2.0-12297.xpi"* | *"premieropinion"* | *"pmropn"*".exe"* | *"360sd"* | *"FileOpenerWindows"* | *"rlvknlg"* | *"ZaxarLoader"* | *"opnsqr"* | *"RestoroProtection"* | *"webcompanion"* | *"RelevantKnowledge"* | *"rlvknlg.exe"*)
					cur="malware"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${bold}${RED}Has malware, Should run a scan with Malwarebytes ADWCleaner Tag=\`premopn\`"
						has="${has} $cur"
					fi
				;;
				*"IDMan"* )
					cur="malware"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${bold}${RED}Has malware, Should run a scan with Malwarebytes Tag=\`malwarebytes\`"
						has="${has} $cur"
					fi
				;;
				*"RPCAcceleratePro.exe"* | *"WebDiscoverBrowser"* )
					cur="pup-$1"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${bold}${YELLOW}Has pup, Should run a scan with Malwarebytes ADWCleaner Tag=\`malewarebytes\`"
						has="${has} $cur"
					fi
					;;
				# *"ipts"*)
				# 	cur="ipts"
				# 	if [[ "${has}" != *" ${cur}"*  ]]; then
				# 		mess="${mess}\n${RED}Has IPTS, Is illegal and should be Removed"
				# 		has="${has} $cur"
				# 	fi
				# 	;;
				*"driverbooster"*)
					cur="gendrvinst"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has a Driver installer, Can cause driver issues. Recommended to remove"
						has="${has} $cur"
					fi
					;;	
				*"RzSynapse"* | *"Raser Synapse"*)
					cur="RzSynapse"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has Razer Synapse, Can cause memory issues. tag=\`hjt.synapse\`"
						has="${has} $cur"
					fi
					;;	
				*"Zonealarm"*)
					cur="Zonealarm"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has Zonealarm,Causes login and multiplayer connectivity problems, degrades performance. <https://www.bleepingcomputer.com/download/zonealarm-uninstall-tool/dl/58/>"
						has="${has} $cur"
					fi
					;;	
				*"overwolf"*)
					cur="overwolf"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has Overwolf, old versions cause crashes. Update Overwolf to fix"
						has="${has} $cur"
					fi
					;;

				*"warsaw"*)
					cur="warsaw"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has Warsaw, Browser hijacker, Removal Recommended"
						has="${has} $cur"
					fi
					;;
				*"netsession_win"*)
					cur="netsession_win"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${RED}Has Akamai NetSession, Removal Recommended"
						has="${has} $cur"
					fi
					;;

				"O17 - DHCP DNS "*)
					ending="\n${YELLOW}DNS ${1:15}| Optional fix \`>>t windns\`" 
					;;

				# *"O4 -"*)
				# 		mess="${mess}\nStartup item: ${1:11}"
				# 	;;
				*"Medal.exe"*)
					cur="medal"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${YELLOW}Has medal, <https://bugs.mojang.com/browse/MC-165010>"
						has="${has} $cur"
					fi
					;;	



		#Good Software Detections
				*"malwarebytes"* | *"mbam"*)
					cur="overwolf"
					if [[ "${has}" != *" ${cur}"*  ]]; then
						mess="${mess}\n${GREEN}Has Malwarebytes, A recommended antimalware"
						has="${has} $cur"
					fi
					;;


		
		# Piracy related



			esac

																							#DXDiag Checks

		elif [[ "$logtype" == "dxdiag" ]]; then

			case "${1}" in
		


				*"Operating System:"*)
					cur="OS"
					if [[ "${has}" != *" ${cur}"*   ]]; then
						mess="${mess}\n> ${NC}Running on ${1:18}"
						has="${has} ${cur}"
					fi
					;;
				*"Processor:"*)
					cur="processordxdiag"
					if [[ "${has}" != *" ${cur}"*   ]]; then
						url="${1:11}"
						url="${url// /+}"
						url="${url//\?/%%3F}"
						url="${url//\$/%%24}"
						mess="${mess}\n> ${NC}Processor:${1:10} (DDG search: <https://duckduckgo.com/?q=${url}>)"
						has="${has} ${cur}"
					fi
					;;
				*"Manufacturer:"*)
					manufacturer=""
					# Deprecated
					# case "${1}" in
					# 	*"Advanced Micro Devices, Inc."* )
					# 		manufacturer="(Download: <https://support.amd.com/en-us/download/auto-detect-tool>)"
					# 		;;
					# 	*"NVIDIA"* )
					# 		manufacturer="(Download: <https://www.nvidia.com/download/index.aspx?lang=en-us>)"
					# 		;;
					# 	*"Intel Corporation"* )
					# 		manufacturer="(Download: <https://downloadcenter.intel.com/>)"
					# 		;;
					# esac  ${manufacturer} 
					mess="${mess}\n> ${NC}${1}"
				;;

				*"Card name:"*)
					url="${1:11}"
					url="${url// /+}"
					url="${url//\?/%%3F}"
					url="${url//\$/%%24}"
					mess="${mess}\n> ${NC}Card name:${1:10} (DDG search: <https://duckduckgo.com/?q=${url}+drivers>)"
					has="${has} ${cur}"
					;;
				"Memory:"* | *"Available OS Memory:"* | *"Chip type:"*)



					mess="${mess}\n> ${NC}${1}"
					;;
				"DxDiag Notes"*)
					mess="${mess}\n${NC}DXDiag notes list"
				;;
				*"Display Tab 1:"*)
					cur="displaytabdxdiag"
					if [[ "${has}" != *" ${cur}"*   ]]; then
						mess="${mess}\n> ${NC}${1}"
						has="${has} ${cur}"
					fi
					;;
				*"Display Tab 2:"*)
					cur="displaytab2dxdiag"
					if [[ "${has}" != *" ${cur}"*   ]]; then
						mess="${mess}\n> ${NC}${1}"
						has="${has} ${cur}"
					fi
					;;
				*"Sound Tab 1:"*)
					cur="soundtabdxdiag"
					if [[ "${has}" != *" ${cur}"*   ]]; then
						mess="${mess}\n> ${NC}${1}"
						has="${has} ${cur}"
					fi
					;;
				*"Input Tab:"*)
					cur="inputtabdxdiag"
					if [[ "${has}" != *" ${cur}"*   ]]; then
						mess="${mess}\n> ${NC}${1}"
						has="${has} ${cur}"
					fi
					;;
				"Display Devices" | "System Information")
					cur="displaydevicesdxdiag"
					if [[ "${has}" != *" ${cur}"*   ]]; then
						mess="${mess}\n${NC}${1}"
						has="${has} ${cur}"
					fi
					;;

			esac
		fi
		if [[ "$cur" != "" ]]; then
			case "$1" in
				"O4 - HKLM..Run\:"* | "O4 - HKUS.DEFAULT..Run\:"* | "O4 - HKUSS-1-5-18..Run\: "* | "Global Startup\:"* | "Startup\:"*)
					if [[ "$mess" != *"; Detected as a start-up registry entry, might not cause issues"* ]];then
						mess="${mess}; Detected as a start-up registry entry, might not cause issues"
					fi
				;;			
				*"\(file missing\)"*)
					if [[ "$mess" != *"; Detected as a missing file, could be a false positive"* ]];then
					mess="${mess}; Detected as a missing file, could be a false positive"
				fi
				;;
				# *"(file missing)"*)
				# 	mess="${mess}; Detected missing, could be a false positive"
				# ;;
				"Trusted Zone\:"*)
					if [[ "$mess" != *"; Detected as a 'Trusted Zone', could be a false positive"* ]];then
						mess="${mess}; Detected as a 'Trusted Zone', could be a false positive"
					fi
				;;

			esac
		fi
		if [[ "$cur" != "None" && "$cur" != *"Ubpastebin"* && "$cur" != "hjtver" ]] ; then
			echo "$1" >> hjtchecker.log
			printf "\n<tr>\n<td class=\"detection\">$1</td>\n<td class=\"tag\">$cur</td>\n</tr>" >> $htmlfile
		elif [[ "$cur" == "hjtver" && "$cur" != "None" ]] ; then
		 	printf "\n${1:74}" >> $htmlfile
		fi
		if [[ "$1" =~ *'Users*[^a-Z0-9]*'* || "$1" =~ *'Users*[^a-Z0-9]*'* ]];then
			cur="invalname"
			if [[ "${has}" != *" ${cur}"*  ]]; then
				printf "\n${RED}Has invalid characters in Windows username(Could be a false positive)"
				has="${has} $cur"
			fi			
		fi
		
}




if [[ "$arg1" == "" || "$allarg" == *"-h"* ]] # --help handling
then
	echo "$(date "+%D@%H:%M") - Printing Help message" > hjtchecker.log
	printf "$usage"
	exit
else
echo "$(date "+%D@%H:%M") - Starting hjtchecker" > hjtchecker.log


	if [[ "$arg1" == "./hjtlog" || "$arg1" == "-r" ]];then
		url="./hjtlog"
		hjtlog="./hjtlog"



	elif [[ "$arg1" != "http://"* && "$arg1" != "https://"* ]]
	then
	
		echo "Argument is invalid!" >> hjtchecker.log
		detect "$argall"
		if [[ "${has}" == "" ]]; then
				printf "${RED}Invalid URL/Argument\n"
		else
				printf "\n${mess}\nDebug(This is a list of all the detection tags):${has}"
				echo "--------------------------------------" >> hjtchecker.log
				echo "$(date "+%H:%M") - Done checking text.." >> hjtchecker.log
				printf "${ending}"
		fi
		exit
		# printf "${NC}Please input a url:"
		# read url
		# if [[ "$url" != "https://paste"* ]]
		# then
		# 	printf "${RED}Error: Invalid URL\n"
		# 	echo "Input is invalid!" >> hjtchecker.log
		# 	exit
		# else
		# 	printf "\nURL looks good, Downloading..."
		# 	echo "Argument is valid" >> hjtchecker.log
		# fi
	else
		#printf "\nURL looks good, Downloading..."
		if [[ "$arg1" == *"/plain/" ]]; then
			printf "Converting to normal log from 'plain'"
			arg1="${arg1:0:-6}"
		fi
		echo "Argument is valid" >> hjtchecker.log
		url="$arg1"
		echo "Downloading log..." >> hjtchecker.log
		rm ${hjtlog}
		#curl ${url} >> ${hjtlog}
		curl -o "${hjtlog}" "${url}"
		echo "Curl ran with exit code $?" >> hjtchecker.log
	fi
 



	printf "<!DOCTYPE html>\n<html>\n<head>\n	<title>Checkhjt detections</title>\n <style>.tag, .detection{\nbackground-color: #eee;\n  border-style: solid;\n  border-color: #222;\n  border-width: 2px;\n  color: black;\n}\n</style>    \n</head>\n<body><h1>Detections</h1><br>Due to a bug with ${me}, slashes are not read at all<br>\n<table>\n <tr>\n<td class=\"detection\">Detection</td>\n<td class=\"tag\">Tag</td>\n</tr>" > $htmlfile

	echo "--------------Detections--------------" >> hjtchecker.log
	line=0

	shopt -s nocasematch
	if [[ "$runmode" == "cli" ]]; then
		printf "\nRunning in CLI mode: Formatting might be broken and tags from detections are for the Discord bot.\n"
	fi

	while read p; do
		line+=1

		detect "$p"

	done <${hjtlog}

	if [[ "$line" == "0" ]]; then
		printf "\n${RED}Unable to download/read log!"
	elif [[ "${has}" == "" ]]; then
		printf "\n${RED}Invalid log/file!"
	
	else
		if [[ "${has}" == " Ubpastebin hjtver platform" ]]; then
			printf "\n${GREEN}Nothing found!"
		else
			printf "${mess}"
		fi
		if [[ "${has}" != *"Ubpastebin"* ]]; then
			printf "\n${RED}Not using Ubuntu Pastebin, This might not be accurate"
		fi
		printf "\n</table>\n<br>Debug(This is a list of all the detection tags):<br>${has}" >> $htmlfile
		printf "\n</body>\n</html>" >> $htmlfile
		echo "--------------------------------------" >> hjtchecker.log
		echo "$(date "+%H:%M") - Done checking log.." >> hjtchecker.log
		printf "${ending}\n${BLUE}Done checking ${logtype} log, Check ${loghtmllink} for more info\n"
	fi
fi
