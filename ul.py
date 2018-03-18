#!/bin/python

"""
Program for running through a UFW log
"""

# Standard library modules
import getopt
import sys


def main(): 
    
    i = 0

    with open('fw.txt', 'r') as f:
        for event in f:
            if "UFW BLOCK" in event:
                time = event[:15]
                mac = event[event.find("MAC=") + 4:event.find("MAC=") + 42]
                srcIp = event[event.find("SRC=") + 4:event.find("SRC=") + 15]
                dstIp = event[event.find("DST=") + 4:event.find("DST=") + 15]
                proto = event[event.find("PROTO=") + 6:event.find("PROTO=") + 9]
                port = event[event.find("DPT=") + 4:event.find("DPT=") + 10]

                if i < 1000:
                    print("Event:", i)
                    print("Time:", time)
                    print("Mac.addr:", mac)
                    print("Source Ip:", srcIp)
                    print("Destination Ip:", dstIp)
                    print("Protocol:", proto)
                    print("Destination Port:", port)

                    print('-' * 50)

                i += 1


def verifier():
    pass

def printer():
    pass

if __name__ == '__main__':
    main()
