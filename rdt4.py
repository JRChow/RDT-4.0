#!/usr/bin/python3
"""Implementation of RDT4.0

functions: rdt_network_init, rdt_socket(), rdt_bind(), rdt_peer()
           rdt_send(), rdt_recv(), rdt_close()

Student name: ZHOU Jingran
Student No. : 3035232468
Date and version: 1 Apr, Version 0
Development platform: Developed on macOS High Sierra (Version 10.13.3); Tested on Ubuntu 16.04 LTS
Python version: Python 3.6.3
"""

import socket
import random

# some constants
PAYLOAD = 1000  # size of data payload of each packet
CPORT = 100  # Client port number - Change to your port number
SPORT = 200  # Server port number - Change to your port number
TIMEOUT = 0.05  # retransmission timeout duration
TWAIT = 10 * TIMEOUT  # TimeWait duration

# store peer address info
__peeraddr = ()  # set by rdt_peer()
# define the error rates and window size
__LOSS_RATE = 0.0  # set by rdt_network_init()
__ERR_RATE = 0.0
__W = 1


# internal functions - being called within the module
def __udt_send(sockd, peer_addr, byte_msg):
    """This function is for simulating packet loss or corruption in an unreliable channel.

    Input arguments: Unix socket object, peer address 2-tuple and the message
    Return  -> size of data sent, -1 on error
    Note: it does not catch any exception
    """
    global __LOSS_RATE, __ERR_RATE
    if peer_addr == ():
        print("Socket send error: Peer address not set yet")
        return -1
    else:
        # Simulate packet loss
        drop = random.random()
        if drop < __LOSS_RATE:
            # simulate packet loss of unreliable send
            print("WARNING: udt_send: Packet lost in unreliable layer!!")
            return len(byte_msg)

        # Simulate packet corruption
        corrupt = random.random()
        if corrupt < __ERR_RATE:
            err_bytearr = bytearray(byte_msg)
            pos = random.randint(0, len(byte_msg) - 1)
            val = err_bytearr[pos]
            if val > 1:
                err_bytearr[pos] -= 2
            else:
                err_bytearr[pos] = 254
            err_msg = bytes(err_bytearr)
            print("WARNING: udt_send: Packet corrupted in unreliable layer!!")
            return sockd.sendto(err_msg, peer_addr)
        else:
            return sockd.sendto(byte_msg, peer_addr)


def __udt_recv(sockd, length):
    """Retrieve message from underlying layer

    Input arguments: Unix socket object and the max amount of data to be received
    Return  -> the received bytes message object
    Note: it does not catch any exception
    """
    (rmsg, peer) = sockd.recvfrom(length)
    return rmsg


def __IntChksum(byte_msg):
    """Implement the Internet Checksum algorithm

    Input argument: the bytes message object
    Return  -> 16-bit checksum value
    Note: it does not check whether the input object is a bytes object
    """
    total = 0
    length = len(byte_msg)  # length of the byte message object
    i = 0
    while length > 1:
        total += ((byte_msg[i + 1] << 8) & 0xFF00) + ((byte_msg[i]) & 0xFF)
        i += 2
        length -= 2

    if length > 0:
        total += (byte_msg[i] & 0xFF)

    while (total >> 16) > 0:
        total = (total & 0xFFFF) + (total >> 16)

    total = ~total

    return total & 0xFFFF


# These are the functions used by appliation

def rdt_network_init(drop_rate, err_rate, W):
    """Application calls this function to set properties of underlying network.

    Input arguments: packet drop probability, packet corruption probability and Window size
    """
    random.seed()
    global __LOSS_RATE, __ERR_RATE, __W
    __LOSS_RATE = float(drop_rate)
    __ERR_RATE = float(err_rate)
    __W = int(W)
    print("Drop rate:", __LOSS_RATE, "\tError rate:", __ERR_RATE, "\tWindow size:", __W)


def rdt_socket():
    """Application calls this function to create the RDT socket.

    Null input.
    Return the Unix socket object on success, None on error

    Note: Catch any known error and report to the user.
    """


######## Your implementation #######

def rdt_bind(sockd, port):
    """Application calls this function to specify the port number
    used by itself and assigns them to the RDT socket.

    Input arguments: RDT socket object and port number
    Return	-> 0 on success, -1 on error

    Note: Catch any known error and report to the user.
    """


######## Your implementation #######

def rdt_peer(peer_ip, port):
    """Application calls this function to specify the IP address
    and port number used by remote peer process.

    Input arguments: peer's IP address and port number
    """


######## Your implementation #######

def rdt_send(sockd, byte_msg):
    """Application calls this function to transmit a message (up to
    W * PAYLOAD bytes) to the remote peer through the RDT socket.

    Input arguments: RDT socket object and the message bytes object
    Return  -> size of data sent on success, -1 on error

    Note: (1) This function will return only when it knows that the
    whole message has been successfully delivered to remote process.
    (2) Catch any known error and report to the user.
    """


######## Your implementation #######

def rdt_recv(sockd, length):
    """Application calls this function to wait for a message from the
    remote peer; the caller will be blocked waiting for the arrival of
    the message. Upon receiving a message from the underlying UDT layer,
    the function returns immediately.

    Input arguments: RDT socket object and the size of the message to
    received.
    Return  -> the received bytes message object on success, b'' on error

    Note: Catch any known error and report to the user.
    """


######## Your implementation #######

def rdt_close(sockd):
    """Application calls this function to close the RDT socket.

    Input argument: RDT socket object

    Note: (1) Catch any known error and report to the user.
    (2) Before closing the RDT socket, the reliable layer needs to wait for TWAIT
    time units before closing the socket.
    """
######## Your implementation #######
