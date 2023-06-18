import time
import threading
import string
import logging
import math
from rtmidi.midiutil import open_midiport
import rtmidi

from winpcapy.winpcapy_types import *

log = logging.getLogger('test_midiin_callback')
logging.basicConfig(level=logging.DEBUG)

# "cubase" or "mackie" or  "hui" mode
midi_protocol = "hui"

midiin_port = "C24 7"
midiout_port = "C24out 11"

midiin, midi_in_port_name = open_midiport(midiin_port)
print("Midi input ports:\n", *rtmidi.MidiIn().get_ports(), sep='\n')

midi_out = rtmidi.MidiOut()
print("\nMidi out ports:\n", *midi_out.get_ports(), sep='\n')
midiout_port_nr = midi_out.get_ports().index(midiout_port)
midi_out.open_port(midiout_port_nr)

midi_loopback = rtmidi.MidiOut()
midi_loopback.open_port(10)

# https://github.com/nmap/npcap/releases/tag/v0.80
##pip install python-rtmidi

mac_computer = [0x70, 0x8B, 0xCD, 0xBA, 0x33, 0xDF]  # mac add of your computer

avid_vendor_mac = [0x00, 0xA0, 0x7E]
mac_c24 = []
brascast_addr = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
net_protocol = [0x88, 0x5f]  # digidesign costom protol id
net_nr_of_bytes = [0x00, 0x00]  # will later be calculated
net_parity = [0x00, 0x00]  # not sure what this is - maybe for parity, i just set to 0
net_counter_var = [0x00, 0x00, 0x00, 0x00]  # incremental packet count nr by the def net_counter()
net_nr_of_commands = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

ch_display = [0xf0, 0x13, 0x01, 0x40, 0x00, 0x00, 0x43, 0x48, 0x20, 0x20, 0xf7]

# VU Mersenne - sohould be calculated
vu_scale_lsb = [0, 1, 3, 7, 15, 31, 63, 127, 127, 127, 127, 127, 127, 127, 127]
vu_scale_msb = [0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 7, 15, 31, 63, 127]

pan_scale_l = [0x20, 0x10, 0x08, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
pan_scale_r = [0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x00]

pan_scale_l2 = [0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01]
pan_scale_r2 = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x60, 0x70, 0x78, 0x7c, 0x7E, 0x01, 0x00]

led_hex_digi = [
    #    0     1     2     3     4     5     6     7
    0x7e, 0x30, 0x6d, 0x79, 0x33, 0x5b, 0x5f, 0x70,
    #    8     9     A     B     C     D     E     F
    0x7f, 0x7b, 0x77, 0x1f, 0x4e, 0x3d, 0x4f, 0x47]

# counter to the net_counter_var
net_packetcount = [0]

interface = b''
fp = pcap_t
errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
PHAND = CFUNCTYPE(None, POINTER(c_ubyte), POINTER(pcap_pkthdr), POINTER(c_ubyte))


class MidiInputHandler(object):
    last_message = None

    def __init__(self, port):
        self.port = port
        self._wallclock = time.time()

    def __call__(self, event, data=None):
        message, deltatime = event
        self._wallclock += deltatime
        print("[%s] @%0.6f %r" % (self.port, self._wallclock, message))

        if midi_protocol == "cubase":
            cubase_generic(message)
        if midi_protocol == "mackie":
            mackie(message)
        if midi_protocol == "hui":
            hui((message, self._wallclock), MidiInputHandler.last_message)

            MidiInputHandler.last_message = (message, self._wallclock)


def cubase_generic(message):
    if message[0] in range(176, 192) and message[1] in [7, 8]:
        fader_nr = 0

        # some logic to handle all 24 faders in one remote "page" -
        if message[1] == 7:
            fader_nr = message[0] - 176
        elif message[1] == 8:
            fader_nr = (message[0] - 176) + 16

        # print("Fader", fader_nr+1, "Value", message[2], "CH", message[1] )

        send_net_packet(1, [0xb0, fader_nr, message[2], 32 + fader_nr, 0x30])

    # Pan
    if message[0] in range(176, 192) and message[1] in [10, 11]:
        pan_ch = message[0] - 176

        if message[1] == 11:
            pan_ch = pan_ch + 16
        print("Pan", pan_ch, "Value", message[2])
        pan = int(message[2] / 10)
        if pan in range(60 - 69):
            pan = 14

        send_net_packet(1, [0xf0, 0x13, 0x01, 0x00, pan_ch, pan_scale_l2[pan], pan_scale_r2[pan], 0xf7])

    # LED VU meter - very hackish, just wanted some VU
    if message[0] in range(176, 192) and message[1] in [9] and message[2] in [0, 65]:
        vu_ch = message[0] - 176

        if 32 < message[2]:
            lsb = 13
            msb = math.floor((message[2]) / 4) - 2
        else:
            lsb = math.floor(message[2] / 2) - 2
            msb = 0
        send_net_packet(2, [0xf0, 0x13, 0x01, 0x10, 32 + vu_ch, vu_scale_msb[msb], vu_scale_lsb[lsb], 0xf7,
                            0xf0, 0x13, 0x01, 0x10, vu_ch, vu_scale_msb[msb], vu_scale_lsb[lsb], 0xf7])


def hui(event, last_event):
    message, deltatime = event

    # fader vol
    if message[0] == 176 and message[1] in range(0, 8) or message[1] in range(32, 40):
        last_message, last_deltatime = last_event
        if last_deltatime == deltatime and last_message[0] == 176:
            send_net_packet(1, [0xb0, last_message[1], last_message[2], message[1], message[2]])

    # Pan - values from 17 - 27
    if message[0] == 176 and message[1] in range(16, 24):
        pan = message[2] - 16
        pan_ch = message[1] - 16
        send_net_packet(1, [0xf0, 0x13, 0x01, 0x00, pan_ch, pan_scale_l2[pan], pan_scale_r2[pan], 0xf7])

    # VU meter
    if message[0] == 160:
        Vu_ch = message[1]
        if message[2] in range(0, 16):
            send_net_packet(1,
                            [0xf0, 0x13, 0x01, 0x10, Vu_ch, vu_scale_msb[message[2]], vu_scale_lsb[message[2]], 0xf7])
        if message[2] in range(16, 29):
            send_net_packet(1, [0xf0, 0x13, 0x01, 0x10, 32 + Vu_ch, vu_scale_msb[message[2] - 16],
                                vu_scale_lsb[message[2] - 16], 0xf7])


def mackie(message):
    fader_offset = 0
    # mackie control
    if message[0] in range(224, 232):
        print("Fader", message[0] - 223 + fader_offset, "Value", message[2] * 8 + message[1])
        # sends 10bit fader pos
        send_net_packet(1,
                        [0xb0, message[0] - 224 + fader_offset, message[2], (message[0] + 32) - 224 + fader_offset,
                         0x30])

    # Pan
    if message[0] == 176 and message[1] in range(48, 56):
        print("Pan", message[1] - 47 + fader_offset, "Value", message[2])
        pan = message[2] - 17  # in cubase the scale is from 17 to 27 and center is 86
        print(pan)
        if pan == 69 or pan == -17:
            pan = 11

        send_net_packet(1, [0xf0, 0x13, 0x01, 0x00, message[1] - 48 + fader_offset, pan_scale_l[pan],
                            pan_scale_r[pan], 0xf7])

    # 4char Channel Display - V,,ery basic - needs logic to handle if you move tracks around.
    if message[0:6] == [240, 0, 0, 102, 20, 18]:
        # some cursor magic numbers (to found out what channel the text belongs to)
        led_channel_map = [0x38, 0x40, 0x48, 0x4d, 0x54, 0x5b, 0x62, 0x69]
        ch = min(led_channel_map, key=lambda x: abs(x - message[6]))
        ch = led_channel_map.index(ch)
        msg_len = len(message)

        l = message[7:msg_len - 1]
        # combine to a acsiistring + removes spaces (aka 32)
        acsiistrin = "".join([chr(c) for c in l if c is not 32])
        print("incomning display update - CH", ch, "msg", acsiistrin)
        ch_display_text(ch, acsiistrin)


def choose_net_interface():
    global interface
    global fp
    global errbuf
    raw_input = input

    alldevs = POINTER(pcap_if_t)()

    ## Retrieve the device list on the local machine
    if pcap_findalldevs(byref(alldevs), errbuf) == -1:
        print("Error in pcap_findalldevs: %s\n", errbuf.value)
        sys.exit(1)
    i = 0
    d = alldevs.contents
    while d:
        i = i + 1
        print("%d. %s" % (i, d.name))

        if (d.description):
            print(" (%s)\n" % (d.description))
        else:
            print(" (No description available)\n")
        if d.next:
            d = d.next.contents
        else:
            d = False
    if (i == 0):
        print("\nNo interfaces found! Make sure WinPcap is installed.\n")
        sys.exit(-1)

    print("Enter the interface number (1-%d):" % (i))
    inum = raw_input('--> ')
    if inum in string.digits:
        inum = int(inum)
    else:
        inum = 0
    if ((inum < 1) | (inum > i)):
        print("\nInterface number out of range.\n")
        ## Free the device list
        pcap_freealldevs(alldevs)
        sys.exit(-1)

    d = alldevs
    for i in range(0, inum - 1):
        d = d.contents.next

    interface = d.contents.name
    # fp = pcap_open_live(interface, 1024, 1, 1000, errbuf)
    print("will use:", d.contents.description)


def convert_to_ctype(packet_buffer):
    ret = (c_ubyte * len(packet_buffer))()
    for i in range(len(packet_buffer)):
        ret[i] = packet_buffer[i]
    return ret


def net_counter():
    global net_counter_var
    net_packetcount[0] += 1
    # print (net_packetcount)
    net_counter_var[3] = net_packetcount[0] & 0xff
    c = net_packetcount[0]
    c >>= 8
    net_counter_var[2] = c & 0xff


def hexstring_to_list(hexstring):
    return [int(hexstring[i:i + 2], 16) for i in range(0, len(hexstring), 2)]


def init_c24():
    global fp
    init_list = ["0010000000000001000000000000e200",
                 "001f0244000000020000000000000001f013013019000000000000000000f7"]

    for items in init_list:
        net_counter()
        init_string = hexstring_to_list(items)
        ipacket = mac_c24 + mac_computer + net_protocol + init_string
        pcap_sendpacket(fp, convert_to_ctype(ipacket), len(ipacket))
        time.sleep(0.1)


def ch_display_text(channel, text):
    ch_display[4] = channel
    text = text.ljust(4)[:4]
    ch_display[6:10] = [ord(c) for c in text]
    send_net_packet(1, ch_display)


def send_net_packet(nr_of_commands, packet):
    net_counter()
    global net_counter_var
    if nr_of_commands:
        net_nr_of_commands[7] = nr_of_commands

    net_nr_of_bytes[1] = len(net_nr_of_bytes + net_parity + net_counter_var + net_nr_of_commands + packet)
    packet = mac_c24 + mac_computer + net_protocol + net_nr_of_bytes + net_parity + net_counter_var + net_nr_of_commands + packet

    if (pcap_sendpacket(fp, convert_to_ctype(packet), len(packet)) != 0):
        print("\nError sending the packet: %s\n" % pcap_geterr(fp))
        sys.exit(3)
    time.sleep(0.00006)


def send_ackt_packet(c1, c2):
    global fp
    net_counter()  # not sure if ack needs to be counted
    ack = hexstring_to_list("001000000000000000000000a000000000")
    ack[10:11] = c1, c2
    act_packet = mac_c24 + mac_computer + net_protocol + ack
    time.sleep(0.001)
    pcap_sendpacket(fp, convert_to_ctype(act_packet), len(act_packet))


def open_ackt_packet():
    global fp
    # net_counter()  # not sure if ack needs to be counted
    ack = hexstring_to_list("001000000000000000000000a000000000")
    ack[10:11] = 0, 0
    act_packet = brascast_addr + mac_computer + net_protocol + ack
    time.sleep(0.001)
    pcap_sendpacket(fp, convert_to_ctype(act_packet), len(act_packet))


def keep_alive():
    while (True):
        print("Thread: Keep Alive")
        time.sleep(10)
        send_net_packet(0, [])


def send_midi(input_data):
    # print (input_data)
    # print ("C24 CC", input_data[30])

    # volume
    if input_data[30] in range(176, 192) and input_data[31] in range(0, 25):
        fader_nr = input_data[31]
        print("Fader nr: ", fader_nr, "Value: ", input_data[32])
        fader_bank = 7

        if fader_nr > 15:
            fader_bank = 8
            fader_nr = fader_nr - 16

        midi_out.send_message([176 + fader_nr, fader_bank, input_data[32]])
        midi_loopback.send_message([176 + fader_nr, fader_bank, input_data[32]])

    # PAN
    if input_data[30] in range(176, 192) and input_data[31] in range(64, 88):
        pan_value = 0
        pan_ch = input_data[31] - 64
        cubase_remote_page = 10

        if input_data[32] > 64:
            pan_value = input_data[32] - 64
            print("PAN nr: ", pan_ch, "CW - with velocity", pan_value)
        if input_data[32] < 64:
            pan_value = 127 - (64 - input_data[32])
            print("PAN nr: ", pan_ch, "ACW - with velocity", pan_value - 127)
        if pan_ch > 15:
            cubase_remote_page = 11
            pan_ch -= 16
            print("PAN page 2", pan_ch)
        midi_out.send_message([176 + pan_ch, cubase_remote_page, pan_value])


def autodiscover_c24(ip_frame):
    global mac_c24
    if ip_frame[0:6] == brascast_addr and ip_frame[6:9] == avid_vendor_mac:
        print("Found a avid device", '{}'.format(':'.join(hex(x) for x in ip_frame[6:12])))
        mac_c24 = ip_frame[6:12]


def _packet_handler(param, header, pkt_data):
    ip_frame = pkt_data[0:header.contents.len]

    if not mac_c24:
        autodiscover_c24(ip_frame)

    if ip_frame[6:12] == mac_c24:
        if int(header.contents.len) > 30:
            if ip_frame[30] == 0x90 or ip_frame[30] == 0xb0:
                send_midi(ip_frame)
                send_ackt_packet(ip_frame[20], ip_frame[21])


def start_pcap_loop():
    global fp
    packet_handler = PHAND(_packet_handler)
    packet_limit = -1  # infinite
    poll_delay = 5
    fp = pcap_open_live(interface, 65536, 0, poll_delay, errbuf)
    pcap_loop(fp, packet_limit, packet_handler, None)


if __name__ == '__main__':
    choose_net_interface()

    # Keep alive thread to the C24
    th = threading.Thread(target=start_pcap_loop)
    th.daemon = True
    th.start()

    while not mac_c24:
        print("Waiting for Control 24")
        open_ackt_packet()
        time.sleep(3)

    print("Will use this interface: ", interface)

    init_c24()

    # init_ch_display()
    for ch in range(24):
        ch_display_text(ch, "Ch" + str(ch + 1))

    # Keep alive thread to the C24
    th = threading.Thread(target=keep_alive)
    th.daemon = True
    th.start()
    midiin.ignore_types(True, True, True)  # Enable SYSX
    midiin.set_callback(MidiInputHandler(midi_in_port_name))

    while True:
        print("main loop")
        time.sleep(60)
