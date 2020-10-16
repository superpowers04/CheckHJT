#!/bin/bash
#echo "We need you to run this as root for diagnostics, If you do not understand what this means then just enter your system password below, It will not show the password for security reasons"

function check {
    printf "Hijackthis alternative for Unix using bash\nRun by:\n$USER \nUname:\n"
    uname -a
    printf "Java -version output:\n"
    java -version 2>&1
    if [[ -e /lib/jvm ]];then
        printf "\nJava installations in /lib/jvm:\n"
        ls /lib/jvm    
    elif [[ -e /lib64/jvm ]];then
        printf "\nJava installations in /lib64/jvm:\n"
        ls /lib64/jvm
    elif [[ -e /Library/Java/JavaVirtualMachines/ ]];then
        printf "\nJava installations in /Library/Java/JavaVirtualMachines/:\n"
        ls /Library/Java/JavaVirtualMachines/
    fi
    printf "\nHost file\n"
    cat /etc/hosts
    if [[ -f "/private/etc/hosts" ]];then
        printf "\nSecond host file\n"
        cat /private/etc/hosts
      fi
    printf "\nProcess List:\n"
    ps -ax
    if [[ -e /Applications ]];then
        printf "\nInstalled applications (Darwin):\n"
        ls -1 /Applications
    else
        printf "\nInstalled applications (/usr/local):\n"
        ls -1 /usr/share/applications
        printf "\nInstalled applications (~/.local/share/applications):\n"
        ls -1 ~/.local/share/applications
        if [[ -f "/usr/bin/pacman" ]]; then
            printf "\nInstalled applications (pacman):\n"
            pacman -Q
        fi
        if [[ -f "/usr/bin/apt" ]]; then
            printf "\nInstalled applications (apt):\n"
            apt list --installed
        fi
    fi
}

case "$@" in
    "-h" )
        printf "Usage:\n -h : Print this help message\n -f : Produce output file instead of uploading\n"
    ;;
    "-f" )
        printf "\nAnalysing..\033[0;1m"
        check > ~/hjtlog
        printf "\n\033[0;1mWe created a file at your home directory called 'hjtlog', Please send this to us\n"
    ;;
    * )
        printf "\nAnalysing.."
        check | curl -F 'sprunge=<-' http://sprunge.us/
        printf "\nPlease give us the link above"
    ;;
esac
