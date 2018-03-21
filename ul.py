#!/bin/python

"""
Program for running through a UFW log
"""

# Standard library modules
import getopt
import subprocess
import sys


def main():
    NO_ARG_FLAG = 0
    FILE_INPUT_FLAG = 0
    FILE_OUTPUT_FLAG = 0

    INPUT_FILE = ''
    FRESH_LOG = ""
    OUTPUT_FILE = ""
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'f:o:nh', ['input-file=', 'output-file=', 'new', 'help'])
    except getopt.GetoptError as e:
        print(e)
        exit(2)

    if opts == []:
        NO_ARG_FLAG = 1
        journal = subprocess.getoutput("journalctl | grep -i ufw")
        FRESH_LOG = converter(journal)
    else:
        for opt, arg in opts:
            if opt in ('-h', '--help'):
                pass
            elif opt in ('-f', '--input-file'):
                FILE_INPUT_FLAG = 1
                with open("fw.txt", "r") as f:
                    INPUT_FILE = converter(f)
            elif opt in ('-o', '--output-file'):
                FILE_OUTPUT_FLAG = 1
                OUTPUT_FILE = opt
            elif opt in ('-n', '--new'):
                journal = subprocess.run("journalctl | grep -i ufw", shell=True)
                FRESH_LOG = converter(journal)

    if FILE_OUTPUT_FLAG == 1 and NO_ARG_FLAG == 1:
        write_to_file(FRESH_LOG)
    elif FILE_OUTPUT_FLAG == 1 and FILE_INPUT_FLAG == 1:
        write_to_file(INPUT_FILE)
    elif FILE_OUTPUT_FLAG == 0 and FILE_INPUT_FLAG == 1:
        print(INPUT_FILE)
    elif NO_ARG_FLAG == 1:
        print(FRESH_LOG)


def system_verifier():
    pass
    #TODO: Verify the following
    """ OS == Linux
        init == SystemD
        Firewall == UFW
    """


def converter(log):
    for event in log:
        # if "UFW BLOCK" in event:
        time = event[:15]
        mac = event[event.find("MAC=") + 4:event.find("MAC=") + 42]
        srcIp = event[event.find("SRC=") + 4:event.find("SRC=") + 15]
        dstIp = event[event.find("DST=") + 4:event.find("DST=") + 15]
        proto = event[event.find("PROTO=") + 6:event.find("PROTO=") + 9]
        port = event[event.find("DPT=") + 4:event.find("DPT=") + 10]
        breaker = "-" * 50

        formattedString = "Time: {}\n" \
                          "Mac address: {}\n" \
                          "Source Ip: {}\n" \
                          "Destination Ip: {}\n" \
                          "Protocol: {}\n" \
                          "Destination Port: {}\n" \
                          "{}".format(time, mac, srcIp, dstIp, proto, port, breaker)

        return(formattedString)


def write_to_file(log):
    with open('firewall_log.txt', 'w') as f:
        f.write(log)


if __name__ == '__main__':
    main()

