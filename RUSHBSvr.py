import binascii
import socket
import struct
import threading
from threading import Timer

HOST = '127.0.0.1'
HEADER_BITS = 64
BYTES_TO_READ = 1464

# FLAGS
ACK = 0
NAK = 1
GET = 2
DAT = 3
FIN = 4
CHK = 5
ENC = 6

# PAYLOAD
SEQ_NUM = 0
HEADER = 1
PAYLOAD = 2
TIMER = 3
CHK_SUM = 4

# CLIENT DATA
SEQ_NUM_SEND = 0
CHK_AGREE = 1
ENC_AGREE = 2
PAYLOADS = 3
DONE = 4
PACKET_TO_SEND = 5
INIT_HEADER = 6

clients_data = dict()


def encrypt(b):
    encrypted = b''
    for c in b:
        i = chr(c)
        if i == 0:
            break
        dec = ord(i)
        value = (dec**11) % 249
        encrypted += bytes([value])
    return encrypted


def decrypt(payload):
    message = ''
    for i in payload:  # i is letter
        if i == 0:
            break
        c = ord(i)
        value = (c**15) % 249
        message += chr(value)
    return message


def get_decimals(payload):
    decs = []
    for i in range(0, len(payload), 2):
        if i + 1 < len(payload):
            two_bytes = struct.pack('>cc', bytes([payload[i]]),
                                    bytes([payload[i + 1]]))
        else:
            two_bytes = struct.pack('>c', bytes(payload[i]))
        res = byte_to_dec(two_bytes)

        decs.append(res)
    return decs


def byte_to_dec(byte):
    return int.from_bytes(byte, byteorder='little')


def tohex(val, nbits):
    return hex((val + (1 << nbits)) % (1 << nbits))


def calc_checksum(message):
    decs = get_decimals(message)
    sum = 0
    for d in decs:
        total = sum + d
        sum = ((total & 0xffff) + (total >> 16))
    return (~sum & 0xffff)


def bin_to_bytes(b):
    n = int(b, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def get_flags_index(flags):
    idxs = []
    for idx, b in enumerate(flags):
        if b == '1':
            idxs.append(idx)
    return idxs


def get_new_flags(
        flagsArray,
        chk_agree=False,
        enc_agree=False):  # get array of flags to set to 1, return flags bit
    flags = ['0'] * 8
    for i in flagsArray:
        flags[i] = '1'
    if chk_agree:
        flags[CHK] = '1'
    if enc_agree:
        flags[ENC] = '1'
    return "".join(flags)


def get_new_header(s, a, c, f, second_byte):
    new_header = struct.pack('>hhHcc', s, a, c, bin_to_bytes(f), second_byte)
    return new_header


def bytes_data(bytes):
    message = []
    for b in bytes:
        message.append(b)
    return message


def get_payloads(file_name, enc_agree):
    b_data = bytes_data(file_name)
    file_name = "".join(map(chr, b_data)).rstrip('\x00')

    # decrypt
    if enc_agree:
        file_name = decrypt(file_name).rstrip('\x00')

    chunks = []
    try:
        with open(file_name, "rb") as f:
            while True:
                chunk = f.read(BYTES_TO_READ)
                if chunk:
                    if enc_agree:
                        chunk = encrypt(chunk)
                    payload = bytearray(chunk)
                    if len(payload) < BYTES_TO_READ:
                        payload += bytes(BYTES_TO_READ - len(payload))
                    # payload.append()
                    chunks.append(payload)
                else:
                    break
    except:
        return False, chunks
    return True, chunks


def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()


def resend_packet(address, header,
                  payload):  # resend packet when timeout
    global udpSocket
    packet = header + payload
    udpSocket.sendto(packet, address)


def get_timer(address, h, p, send):
    timer = Timer(4.0, resend_packet, args=(address, h, p))
    if send:
        timer.start()
    return timer


# append list of [] to payloads, return packet with header + p
def send_packet(socket,
                address,
                seq_num_send,
                seq_num,
                chksum,
                second,
                type,
                payloads,
                p=None,
                append=True,
                chk_agree=False,
                enc_agree=False,
                send=True):
    s = seq_num_send
    a = seq_num
    c = chksum
    f = get_new_flags(type, chk_agree, enc_agree)

    if not p:
        p = bytearray() + bytes(BYTES_TO_READ)

    if chk_agree:
        c = calc_checksum(bytes(p))
    else:
        c = 0

    # new header and p for each p
    new_h = get_new_header(s, a, c, f, second)

    new_packet = new_h + p

    # For each two bytes
    if send:
        with udpSockLock:
            socket.sendto(new_packet, address)

    # create tuple and append to payloads
    if append:
        timer = get_timer(address, new_h, p, send)
        payloads.append([s, new_h, p, timer, c])


def send_next_packet(socket, address, header, p):
    pass


def handle_req(udpSocket, data, address, seq_num_send, chk_agree, enc_agree,
               payloads, packet_to_send, init_header):

    done = False

    header = data[:8]
    payload = data[8:]

    seq_num, ack_num, chksum, first, second = struct.unpack(">hhHcc", header)
    flags = format(int(binascii.hexlify(first).decode(), 16),
                   '08b')  # 00100000

    # get payloads
    if int(flags[GET]):
        chk_agree = bool(int(flags[CHK]))
        enc_agree = bool(int(flags[ENC]))
        found, send_payloads = get_payloads(payload, enc_agree)
        if found:
            # for each payload, send the packet
            for p in send_payloads:
                seq_num_send += 1
                send_packet(udpSocket,
                            address,
                            seq_num_send,
                            seq_num if int(flags[ACK]) else 0,
                            chksum,
                            second, [DAT],
                            payloads,
                            p,
                            chk_agree=chk_agree,
                            enc_agree=enc_agree,
                            send=True if seq_num_send == 1 else False)

        # Send FIN
        else:
            seq_num_send += 1
            send_packet(udpSocket,
                        address,
                        seq_num_send,
                        0,
                        chksum,
                        second, [FIN],
                        payloads,
                        chk_agree=chk_agree,
                        enc_agree=enc_agree)

    if chk_agree and chksum == calc_checksum(payload) or not chk_agree:
        valid_packet = True
    else:
        valid_packet = False

    if valid_packet:
        # Receive ACK
        if (int(flags[DAT]) or int(flags[FIN]) or int(flags[NAK])) and int(
                flags[ACK]):
            # TURN OFF TIMER !!!
            for p_list in payloads:
                if p_list[SEQ_NUM] == ack_num:
                    p_list[TIMER].cancel()
                    p_list[TIMER].join()
            if int(flags[FIN]) and int(flags[ACK]):
                seq_num_send += 1
                send_packet(udpSocket,
                            address,
                            seq_num_send,
                            seq_num,
                            chksum,
                            second, [ACK, FIN],
                            payloads,
                            chk_agree=chk_agree,
                            enc_agree=enc_agree)
                done = True

            if (int(flags[DAT]) or int(flags[NAK])) and int(flags[ACK]):
                finish = packet_to_send == len(payloads) - 1
                # check all DAT packets are sent and received
                for p_list in payloads:
                    if p_list[TIMER].is_alive():
                        finish = False
                        break
                if finish:
                    seq_num_send += 1
                    send_packet(udpSocket,
                                address,
                                seq_num_send,
                                0,
                                chksum,
                                second, [FIN],
                                payloads,
                                chk_agree=chk_agree,
                                enc_agree=enc_agree)
                else:  # Send the next packet
                    packet_to_send += 1
                    h = payloads[packet_to_send][HEADER]
                    p = payloads[packet_to_send][PAYLOAD]
                    payloads[packet_to_send][TIMER].cancel()
                    payloads[packet_to_send][TIMER].start()
                    new_packet = h + p
                    with udpSockLock:
                        udpSocket.sendto(new_packet, address)

        # Server received NAK
        if int(flags[NAK]) and int(flags[DAT]):
            # Find in the record the payloads with s = ack_number
            for p_list in payloads:
                if p_list[SEQ_NUM] == ack_num:
                    h = p_list[HEADER]
                    p = p_list[PAYLOAD]
                    new_packet = h + p
                    with udpSockLock:
                        udpSocket.sendto(new_packet, address)
                    # cancel the old timer
                    p_list[TIMER].cancel()
                    p_list[TIMER].join()
                    p_list[TIMER] = get_timer(address, h,
                                              p_list[PAYLOAD], send=True)

        # Reset Cache: seq_num_send, payloads, last_packet_sqn
    return (seq_num_send, chk_agree, enc_agree, payloads, done, packet_to_send,
            init_header)


def handle_client(udpSocket, data, address):
    global clients_data

    key = address[0] + str(address[1])

    c = clients_data[key]
    seq_num_send = c[SEQ_NUM_SEND]
    chk_agree = c[CHK_AGREE]
    enc_agree = c[ENC_AGREE]
    payloads = c[PAYLOADS]
    packet_to_send = c[PACKET_TO_SEND]
    init_header = c[INIT_HEADER]

    c[SEQ_NUM_SEND], c[CHK_AGREE], c[ENC_AGREE], c[PAYLOADS], c[DONE], c[
        PACKET_TO_SEND], c[INIT_HEADER] = handle_req(udpSocket, data, address,
                                                     seq_num_send, chk_agree,
                                                     enc_agree, payloads,
                                                     packet_to_send,
                                                     init_header)


udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udpSockLock = threading.Lock()
udpSocket.bind((HOST, 0))
port = udpSocket.getsockname()[1]

print(port, flush=True)

while True:
    data, address = udpSocket.recvfrom(1500)

    key = address[0] + str(address[1])  # (addr + port number) string

    if key in clients_data.keys():
        if clients_data[key][DONE]:
            del clients_data[key]

    if not key in clients_data.keys():
        clients_data[key] = [0, False, False, [], False, 0, None]

    c_thread = threading.Thread(target=handle_client,
                                args=(udpSocket, data, address))
    c_thread.daemon = True
    c_thread.start()
