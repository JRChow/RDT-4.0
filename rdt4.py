#!/usr/bin/python3
"""Implementation of RDT4.0

functions: rdt_network_init, rdt_socket(), rdt_bind(), rdt_peer()
           rdt_send(), rdt_recv(), rdt_close()

Student name: ZHOU Jingran
Student No. : 3035232468
Date and version: 3 Apr, Version 2
Development platform: Developed on macOS High Sierra (Version 10.13.3);
                      Tested on Ubuntu 16.04 LTS
Python version: Python 3.6.3
"""

import socket
import random
import math
import select
import struct

# Some constants
PAYLOAD = 1000  # size of data payload of each packet
CPORT = 100  # Client port number - Change to your port number
SPORT = 200  # Server port number - Change to your port number
TIMEOUT = 0.05  # retransmission timeout duration
TWAIT = 10 * TIMEOUT  # TimeWait duration
TYPE_DATA = 12  # 12 means data
TYPE_ACK = 11  # 11 means ACK
MSG_FORMAT = 'BBHH'  # Format string for header structure
HEADER_SIZE = 6  # 6 bytes
SEQ_SIZE = 256  # 2^8 = 256; Sequence number in [0, 255]

# Store peer address info
__peeraddr = ()  # set by rdt_peer()

# Define the error rates and window size
__LOSS_RATE = 0.0  # set by rdt_network_init()
__ERR_RATE = 0.0  # set by rdt_network_init()
__W = 1  # set by rdt_network_init()

# Sequence-number-related global variables
__next_seq_num = 0  # Next sequence number for sender (initially 0)
__exp_seq_num = 0  # Expected sequence number for receiver (initially 0)
__S = 0  # Sender base

# Other global variables
__N = 1  # Number of packets to be sent
__data_buffer = []  # Data buffer


# Internal functions - being called within the module
def __udt_send(sockd, peer_addr, byte_msg):
    """This function is for simulating packet loss or corruption in an
    unreliable channel.

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

    Input arguments: Unix socket object and the max amount of data to be
    received
    Return  -> the received bytes message object
    Note: it does not catch any exception
    """
    (rmsg, peer) = sockd.recvfrom(length)
    return rmsg


def __int_chksum(byte_msg):
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


# These are the functions used by application

def rdt_network_init(drop_rate, err_rate, w):
    """Application calls this function to set properties of underlying network.

    Input arguments: packet drop probability, packet corruption probability
    and Window size
    """
    random.seed()
    global __LOSS_RATE, __ERR_RATE, __W
    __LOSS_RATE = float(drop_rate)
    __ERR_RATE = float(err_rate)
    __W = int(w)
    print("Drop rate:", __LOSS_RATE, "\tError rate:", __ERR_RATE,
          "\tWindow size:", __W)


def rdt_socket():
    """Application calls this function to create the RDT socket.

    Null input.
    Return the Unix socket object on success, None on error

    Note: Catch any known error and report to the user.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error as err_msg:
        print("Socket creation error: ", err_msg)
        return None
    return sock


def rdt_bind(sockd, port):
    """Application calls this function to specify the port number
    used by itself and assigns them to the RDT socket.

    Input arguments: RDT socket object and port number
    Return	-> 0 on success, -1 on error

    Note: Catch any known error and report to the user.
    """
    try:
        sockd.bind(("", port))
    except socket.error as err_msg:
        print("Socket bind error: ", err_msg)
        return -1
    return 0


def rdt_peer(peer_ip, port):
    """Application calls this function to specify the IP address
    and port number used by remote peer process.

    Input arguments: peer's IP address and port number
    """
    global __peeraddr
    __peeraddr = (peer_ip, port)


# -----------------------------------------------------------------------------
# Some helper functions

def __count_pkt(data):
    """
    Count the number of packets that will be generated.
    Input arguments: data
    Return  -> number of packets that will be generated
    """
    return int(math.ceil(
        float(len(data)) / PAYLOAD))  # float() to prevent rounding down


def __make_data(seq_num, data):
    """Make DATA [seq_num].

    Input arguments: sequence number, data, checksum
    Return  -> assembled packet
    """
    # Header
    # {
    # __Type        (1 byte)
    # __Seq num     (1 byte)
    # __Checksum    (2 bytes)
    # __Payload len (2 bytes)
    # }

    # Make initial message
    msg_format = struct.Struct(MSG_FORMAT)
    checksum = 0  # First set checksum to 0
    init_msg = msg_format.pack(TYPE_DATA, seq_num, checksum,
                               socket.htons(len(data))) + data

    # Calculate checksum
    checksum = __int_chksum(bytearray(init_msg))
    # print("checksum = " + str(checksum))

    # A complete msg with checksum
    complete_msg = msg_format.pack(TYPE_DATA, seq_num, checksum,
                                   socket.htons(len(data))) + data
    # print("__make_data() finished --> " + str(__unpack_helper(complete_msg)))
    return complete_msg


def __cut_msg(byte_msg):
    """Ensure data is not longer than max PAYLOAD.
    Input argument: message
    Return  -> (data for one packet, the remaining message)"""
    if len(byte_msg) > PAYLOAD:
        data = byte_msg[0:PAYLOAD]
        remaining = byte_msg[PAYLOAD:]
    else:
        data = byte_msg
        remaining = None
    return data, remaining


def __unpack_helper(msg):
    """Helper function to unpack msg.
    Note: Byte order conversion is done here for length field."""
    size = struct.calcsize(MSG_FORMAT)
    (msg_type, seq_num, recv_checksum, payload_len), payload = struct.unpack(
        MSG_FORMAT, msg[:size]), msg[size:]
    return (msg_type, seq_num, recv_checksum,
            socket.ntohs(payload_len)), payload  # Byte order conversion


def __is_corrupt(recv_pkt):
    """Check if the received packet is corrupted.

    Input arguments: received packet
    Return  -> True if corrupted, False if not corrupted.
    """
    # Header
    # {
    # __Type        (1 byte)
    # __Seq num     (1 byte)
    # __Checksum    (2 bytes)
    # __Payload len (2 bytes)
    # __Payload
    # }

    # print("is_corrupt() checking msg -> " + str(__unpack_helper(recv_pkt)))

    # Dissect received packet
    (msg_type, seq_num, recv_checksum, payload_len), payload = __unpack_helper(
        recv_pkt)
    # print("           : received checksum = ", recv_checksum)

    # Reconstruct initial message
    init_msg = struct.Struct(MSG_FORMAT).pack(msg_type, seq_num, 0,
                                              socket.htons(
                                                  payload_len)) + payload

    # Calculate checksum
    calc_checksum = __int_chksum(bytearray(init_msg))
    # print("           : calc checksum = ", calc_checksum)

    result = recv_checksum != calc_checksum
    # print("corrupt -> " + str(result))

    return result


def __is_type_between(recv_pkt, pkt_type, low, high):
    """Check if the received packet is pkt_type between low and high (inclusive).

    Input arguments: received packet, packet type, lower bound, upper bound
    Return  -> True if received pkt_type w/ seq# in [low, high]
    Note: Allow high to overflow temporarily.
    """
    # Dissect the received packet
    (recv_type, recv_seq_num, _, _), _ = __unpack_helper(recv_pkt)
    if recv_seq_num < low:  # Modular arithmetic case
        recv_seq_num += SEQ_SIZE
    return recv_type == pkt_type and low <= recv_seq_num <= high


def __is_type(recv_pkt, pkt_type):
    """Check if the received packet is pkt_type

    Input arguments: the received packet, pkt_type

    Return  -> True if so; False otherwise.
    """
    (recv_type, _, _, _), _ = __unpack_helper(recv_pkt)
    return recv_type == pkt_type


def __make_ack(seq_num):
    """Make ACK [seq_num].

    Input argument: sequence number
    Return  -> assembled ACK packet
    """
    # print("making ACK " + str(seq_num))

    # Header
    # {
    # __Type        (1 byte)
    # __Seq num     (1 byte)
    # __Checksum    (2 bytes)
    # __Payload len (2 bytes)
    # __Payload
    # }

    # Make initial message
    msg_format = struct.Struct(MSG_FORMAT)
    checksum = 0  # First set checksum to 0
    init_msg = msg_format.pack(TYPE_ACK, seq_num, checksum,
                               socket.htons(0)) + b''

    # Calculate checksum
    checksum = __int_chksum(bytearray(init_msg))
    # print("checksum = ", checksum)

    # A complete msg with checksum
    return msg_format.pack(TYPE_ACK, seq_num, checksum, socket.htons(0)) + b''


def __has_seq(recv_msg, seq_num):
    """Check if the received packet has sequence number [seq_num]

    Input arguments: received packet, sequence number
    Return True if received packet of sequence number [seq_num]
    and False otherwise
    """
    # Dissect the received packet
    (_, recv_seq_num, _, _), _ = __unpack_helper(recv_msg)
    return recv_seq_num == seq_num


def __parse(msg):
    """Parse message for printing."""
    if __is_corrupt(msg):
        return "Corrupt"
    msg_str = ""
    (msg_type, seq_num, checksum, payload_len), payload = __unpack_helper(msg)
    if msg_type == TYPE_DATA:
        msg_str += "DATA"
    elif msg_type == TYPE_ACK:
        msg_str += "ACK"
    msg_str += "[%d]" % seq_num
    if payload_len > 0:
        msg_str += " of size %d" % payload_len
    if 0 < payload_len <= 20:
        msg_str += " -> " + str(payload)
    return msg_str


def __seq_add(a, b):
    """Add sequence numbers (wrap-around) """
    return (a + b) % SEQ_SIZE


def __seq_sub(a, b):
    """Subtract sequence numbers (wrap-around)"""
    return (a - b + SEQ_SIZE) % SEQ_SIZE


# ------------------------------------------------------------------
# Send, receive, close.


def rdt_send(sockd, byte_msg):
    """Application calls this function to transmit a message (up to
    W * PAYLOAD bytes) to the remote peer through the RDT socket.

    Input arguments: RDT socket object and the message bytes object
    Return  -> size of data sent on success, -1 on error

    Note: (1) This function will return only when it knows that the
    whole message has been successfully delivered to remote process.
    (2) Catch any known error and report to the user.
    """
    global __S, __next_seq_num, __N, __data_buffer
    whole_msg_len = len(byte_msg)  # Size of the whole message, to be returned

    # Count how many packets needed to send byte_msg
    __N = __count_pkt(byte_msg)

    snd_pkt = [None] * __N  # Packets to be sent
    first_unacked_ind = 0  # Index of the first unACKed packet
    __S = __next_seq_num  # Update sender base

    print("send(): gonna send %d packets..." % __N)

    # Compose and send all data packets
    for i in range(__N):
        data, byte_msg = __cut_msg(byte_msg)  # Extract from remaining msg
        snd_pkt[i] = __make_data(__next_seq_num, data)  # Make data packet
        # Send the new packet
        try:
            __udt_send(sockd, __peeraddr, snd_pkt[i])
        except socket.error as err_msg:
            print("send(): Socket send error: ", err_msg)
            return -1
        print("send(): sent " + __parse(snd_pkt[i]))

        # Increment sequence number
        __next_seq_num = __seq_add(__next_seq_num, 1)

    r_sock_list = [sockd]  # Used in select.select()
    while True:  # While not received all ACKs
        # Wait for ACK or timeout
        r, _, _ = select.select(r_sock_list, [], [], TIMEOUT)
        if r:  # ACK (or DATA) came
            for sock in r:
                # Try to receive ACK (or DATA)
                try:
                    # Include header
                    recv_pkt = __udt_recv(sock, PAYLOAD + HEADER_SIZE)
                except socket.error as err_msg:
                    print("__udt_recv error: ", err_msg)
                    return -1
                print("send(): received " + __parse(recv_pkt))

                # If corrupted, print and ignore
                if __is_corrupt(recv_pkt):
                    print("send(): receive corrupt -> ignore")
                # If is not corrupted ACK
                elif __is_type(recv_pkt, TYPE_ACK):
                    # Out-of-range, print and ignore
                    if not __is_type_between(recv_pkt, TYPE_ACK, __S,
                                             __S + __N - 1):
                        print("send(): receive out-of-range ACK -> ignore")
                    # In range, accept and set ACK status
                    elif __is_type_between(recv_pkt, TYPE_ACK, __S,
                                           __S + __N - 2):
                        print("send(): range [%d, %d] -> accept ACK" % (
                            __S, __S + __N - 2))
                        (_, recv_seq_num, _, _), _ = __unpack_helper(recv_pkt)
                        # Update first unACKed index (cumulative ACK)
                        first_unacked_ind = max(
                            __seq_sub(recv_seq_num, __S) + 1,
                            first_unacked_ind)
                    # Last ACK (received all ACKs), return
                    elif __is_type_between(recv_pkt, TYPE_ACK, __S + __N - 1,
                                           __S + __N - 1):
                        return whole_msg_len  # Return size of data sent
                # If is a not corrupt DATA
                elif __is_type(recv_pkt, TYPE_DATA):
                    print("send(): ! Receive " + __parse(recv_pkt))
                    # If expected, buffer and ACK
                    if __has_seq(recv_pkt,
                                 __exp_seq_num):
                        print("send(): ! Buffer expected (%d)" % __exp_seq_num)
                        # If not in buffer, add msg to buffer
                        if recv_pkt not in __data_buffer:
                            __data_buffer.append(recv_pkt)
                            print("send(): ! Buffered")
                        # ACK the expected DATA
                        try:
                            __udt_send(sockd, __peeraddr,
                                       __make_ack(__exp_seq_num))
                        except socket.error as err_msg:
                            print("send(): Error in sending ACK to received "
                                  "data: " + str(
                                    err_msg))
                            return -1
                        print("send(): ! Sent ACK[%d]" % __exp_seq_num)
                    # If DATA not expected, send ACK to expected - 1
                    else:
                        # Send ACK for the one prior to the expected
                        try:
                            __udt_send(sockd, __peeraddr, __make_ack(
                                (__seq_sub(__exp_seq_num, 1))))
                        except socket.error as err_msg:
                            print("send(): Error in ACK-ing expected data: " +
                                  str(err_msg))
                            return b''
                        print(
                            "send(): ! Buffer NOT expected (%d) -> sent ACK["
                            "%d]" % (
                                __exp_seq_num,
                                __seq_sub(__exp_seq_num, 1)))
        # Timeout
        else:
            print("* TIMEOUT!")
            # Re-transmit all unACKed packets
            for i in range(first_unacked_ind, __N):
                try:
                    __udt_send(sockd, __peeraddr, snd_pkt[i])
                    print("* send(): resent " + __parse(snd_pkt[i]))
                except socket.error as err_msg:
                    print("Socket send error: ", err_msg)
                    return -1


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
    global __exp_seq_num, __data_buffer

    # Check if something in buffer
    while len(__data_buffer) > 0:
        # Pop data in a FIFO manner
        recv_pkt = __data_buffer.pop(0)  # Guaranteed to be NOT corrupt
        print("recv(): ! Something in buffer -> " + __parse(recv_pkt))

        # Buffered data has expected seq num, happily accept and return
        if __has_seq(recv_pkt, __exp_seq_num):
            print("recv(): ! Buffer expected (%d)" % __exp_seq_num)
            # Increment expected sequence number
            __exp_seq_num = __seq_add(__exp_seq_num, 1)
            (_), payload = __unpack_helper(recv_pkt)  # Extract payload
            return payload

    while True:  # Repeat until received expected DATA
        # Try to receive packet...
        try:
            recv_pkt = __udt_recv(sockd, length + HEADER_SIZE)
        except socket.error as err_msg:
            print("recv(): Socket receive error: " + str(err_msg))
            return b''
        print("recv(): received " + __parse(recv_pkt))

        # If packet is corrupt or is ACK, print and ignore
        if __is_corrupt(recv_pkt) or __is_type(recv_pkt, TYPE_ACK):
            print("recv(): Received corrupted or ACK -> ignore")

        # If received DATA
        elif __is_type(recv_pkt, TYPE_DATA):
            # If DATA has expected seq num, happily accept
            if __has_seq(recv_pkt, __exp_seq_num):
                # Send ACK for this expected packet
                try:
                    __udt_send(sockd, __peeraddr, __make_ack(__exp_seq_num))
                except socket.error as err_msg:
                    print("recv(): Error in ACK-ing expected data: " + str(
                        err_msg))
                    return b''
                print("recv(): expected -> sent ACK[%d]" % __exp_seq_num)
                # Increment expected sequence number
                __exp_seq_num = __seq_add(__exp_seq_num, 1)
                (_), payload = __unpack_helper(recv_pkt)  # Extract payload
                return payload
            # If DATA is not expected
            else:
                # Send ACK for the one prior to the expected
                try:
                    __udt_send(sockd, __peeraddr,
                               __make_ack(__seq_sub(__exp_seq_num, 1)))
                except socket.error as err_msg:
                    print("recv(): Error in ACK-ing expected data: " + str(
                        err_msg))
                    return b''
                print("recv(): NOT expected (%d) -> sent ACK[%d]" % (
                    __exp_seq_num, __seq_sub(__exp_seq_num, 1)))


def rdt_close(sockd):
    """Application calls this function to close the RDT socket.

    Input argument: RDT socket object

    Note: (1) Catch any known error and report to the user.
    (2) Before closing the RDT socket, the reliable layer needs to wait for
    TWAIT time units before closing the socket.
    """
    r_sock_list = [sockd]  # Used in select.select()

    ok_to_close = False  # If has been quiet for a while

    while not ok_to_close:
        r, _, _ = select.select(r_sock_list, [], [],
                                TWAIT)  # Wait for TWAIT time
        if r:  # Incoming activity
            for sock in r:
                # Try to receive (include header size)
                try:
                    recv_pkt = __udt_recv(sock, PAYLOAD + HEADER_SIZE)
                except socket.error as err_msg:
                    print("close(): __udt_recv error: ", err_msg)
                print("close(): Got activity -> " + __parse(recv_pkt))
                # print("close(): __S = %d, __N = %d" % (__S, __N))

                # If not corrupt
                if not __is_corrupt(recv_pkt):
                    # Ack the DATA packet
                    (_, recv_seq_num, _, _), _ = __unpack_helper(recv_pkt)
                    try:
                        __udt_send(sockd, __peeraddr, __make_ack(recv_seq_num))
                    except socket.error as err_msg:
                        print("close(): Error in ACK-ing data: " + str(
                            err_msg))
                    print("close(): Sent last ACK[%d]")
        else:  # Timeout
            print("close(): time to CLOSE!")
            ok_to_close = True
            # Close socket
            try:
                sockd.close()
            except socket.error as err_msg:
                print("Socket close error: ", err_msg)
