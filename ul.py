#!/bin/python

"""
Program for running through a UFW log
"""

# Standard library modules
import getopt
import sys


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'f:o:h', ['input-file=', 'output-file=', 'help'])
    except getopt.GetoptError as e:
        print(e)
        exit(2)

    INPUT_FLAG = False
    OUTPUT_FLAG = False

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            pass
        elif opt in ('-f', '--input-file'):
            INPUT_FLAG = True
            with open("fw.txt", "r") as f:
                INPUT_FILE = converter(f)
        elif opt in ('-o', '--output-file'):
            OUTPUT_FLAG = True
            OUTPUT_FILE = opt
        else:
            f = "something"
            FRESH_LOG = converter(f)

    if OUTPUT_FLAG == True:
        write_to_file(FRESH_LOG)
    elif OUTPUT_FILE == True and INPUT_FLAG == True:
        write_to_file(INPUT_FILE)
    else:
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
            if "UFW BLOCK" in event:
                time = event[:15]
                mac = event[event.find("MAC=") + 4:event.find("MAC=") + 42]
                srcIp = event[event.find("SRC=") + 4:event.find("SRC=") + 15]
                dstIp = event[event.find("DST=") + 4:event.find("DST=") + 15]
                proto = event[event.find("PROTO=") + 6:event.find("PROTO=") + 9]
                port = event[event.find("DPT=") + 4:event.find("DPT=") + 10]
                breaker = "-" * 50
                
                if i < 1000:
                    formattedString = "Event: {}\n" \
                          "Time: {}\n" \
                          "Mac address: {}\n" \
                          "Source Ip: {}\n" \
                          "Destination Ip: {}\n" \
                          "Protocol: {}\n" \
                          "Destination Port: {}\n" \
                                      "{}".format(i, time, mac, srcIp, dstIp, proto, port, breaker)
                    return(formattedString)

                i += 1


def write_to_file(log):
    with open('firewall_log.txt', 'w') as f:
        f.write(inputer)


if __name__ == '__main__':
    main()

