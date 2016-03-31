#Create a linear version that completes auth.  Deal with other shit later.
import socket
from struct import pack, unpack, calcsize
from binascii import hexlify
from threading import Thread, Semaphore
from queue import Queue
from collections import defaultdict
import math
import logging

#All Non-obselete Server->Client protocols
TOCLIENT_AUTH_ACCEPT = 0x03
TOCLIENT_ACCEPT_SUDO_MODE = 0x04
TOCLIENT_DENY_SUDO_MODE = 0x05
TOCLIENT_INIT_LEGACY = 0x10
TOCLIENT_ACCESS_DENIED = 0x0A
TOCLIENT_ADDNODE = 0x21
TOCLIENT_REMOVENODE = 0x22
TOCLIENT_INVENTORY = 0x27
TOCLIENT_TIME_OF_DAY = 0x29
TOCLIENT_CHAT_MESSAGE = 0x30
TOCLIENT_ACTIVE_OBJECT_REMOVE_ADD = 0x31
TOCLIENT_ACTIVE_OBJECT_MESSAGES = 0x32
TOCLIENT_HP = 0x33
TOCLIENT_MOVE_PLAYER = 0x34
TOCLIENT_ACCESS_DENIED_LEGACY = 0x35
TOCLIENT_DEATHSCREEN = 0x37
TOCLIENT_MEDIA = 0x38
TOCLIENT_TOOLDEF = 0x39
TOCLIENT_NODEDEF = 0x3a
TOCLIENT_CRAFTITEMDEF = 0x3b
TOCLIENT_ANNOUNCE_MEDIA = 0x3c
TOCLIENT_ITEMDEF = 0x3d
TOCLIENT_PLAY_SOUND = 0x3f
TOCLIENT_STOP_SOUND = 0x40
TOCLIENT_PRIVILEGES = 0x41
TOCLIENT_INVENTORY_FORMSPEC = 0x42
TOCLIENT_DETACHED_INVENTORY = 0x43
TOCLIENT_SHOW_FORMSPEC = 0x44
TOCLIENT_MOVEMENT = 0x45
TOCLIENT_SPAWN_PARTICLE = 0x46
TOCLIENT_ADD_PARTICLESPAWNER = 0x47
TOCLIENT_DELETE_PARTICLESPAWNER_LEGACY = 0x48
TOCLIENT_HUDADD = 0x49
TOCLIENT_HUDRM = 0x4a
TOCLIENT_HUDCHANGE = 0x4b
TOCLIENT_HUD_SET_FLAGS = 0x4c
TOCLIENT_HUD_SET_PARAM = 0x4d
TOCLIENT_BREATH = 0x4e
TOCLIENT_SET_SKY = 0x4f
TOCLIENT_OVERRIDE_DAY_NIGHT_RATIO = 0x50
TOCLIENT_LOCAL_PLAYER_ANIMATIONS = 0x51
TOCLIENT_EYE_OFFSET = 0x52
TOCLIENT_DELETE_PARTICLESPAWNER = 0x53
TOCLIENT_SRP_BYTES_S_B = 0x60
TOCLIENT_NUM_MSG_TYPES = 0x61

#All client->server protocol headers
TOSERVER_INIT = 0x02
TOSERVER_INIT_LEGACY = 0x10
TOSERVER_INIT2 = 0x11
TOSERVER_PLAYERPOS = 0x23
TOSERVER_GOTBLOCKS = 0x24
TOSERVER_DELETEDBLOCKS = 0x25
TOSERVER_INVENTORY_ACTION = 0x31
TOSERVER_CHAT_MESSAGE = 0x32
TOSERVER_DAMAGE = 0x35
TOSERVER_PASSWORD_LEGACY = 0x36
TOSERVER_PLAYERITEM = 0x37
TOSERVER_RESPAWN = 0x38
TOSERVER_INTERACT = 0x39
TOSERVER_REMOVED_SOUNDS = 0x3a
TOSERVER_NODEMETA_FIELDS = 0x3b
TOSERVER_INVENTORY_FIELDS = 0x3c
TOSERVER_REQUEST_MEDIA = 0x40
TOSERVER_RECEIVED_MEDIA = 0x41
TOSERVER_BREATH = 0x42
TOSERVER_CLIENT_READY = 0x43
TOSERVER_FIRST_SRP = 0x50
TOSERVER_SRP_BYTES_A = 0x51
TOSERVER_SRP_BYTES_M = 0x52
TOSERVER_NUM_MSG_TYPES = 0x53

#Example intro message
    # 0x0000:  4500 005b 0bbf 4000 4011 30d1 7f00 0001
    # 0x0010:  7f00 0001 8682 7530 0047 fe5a 
    # 4f45 7403     protocol id
    # 0002          sender peer id
    # 01            channel
    # 01            packet type
    # 0010          command type
    # 1a            SER_FM_VER_HIGHEST_READ 26
    # 61 7364 6600 0000 0000 0000 0000 0000 0000 0000 00                            username[]20
    # 00 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 00        password[28]
    # 00 0d   min protocol 0
    # 00 1a   max protocol 26

#Example protocol 25 message
    # 4500 0033 0bc0 4000 4011 30f8 7f00 0001
    # 7f00 0001 8682 7530 001f fe32 
    # 4f45 7403         protocol id
    # 0002              sender peer id
    # 01                chanel
    # 01                packet type
    # 0002              command type
    # 1a                u8 serialisation version (=SER_FMT_VER_HIGHEST_READ)
    # 00 00             u16 supported network compression modes
    # 00 0d             u16 minimum supported network protocol version
    # 00 1a             u16 maximum supported network protocol version
    # 00 0461 7364 66   std::string player name (length u16) + string

#Example server response auth
    # 0x0000:  4500 0038 0bc1 4000 4011 30f2 7f00 0001
    # 0x0010:  7f00 0001 7530 8682 0024 fe37 4f45 7403
    # 0x0020:  0001 0003 ffdd 0100 021a 0000 001a 0000
    # 0x0030:  0002 0004 6173 6466

# Packet types.
CONTROL = 0x00
ORIGINAL = 0x01
SPLIT = 0x02
RELIABLE = 0x03

# Types of CONTROL packets.
CONTROLTYPE_ACK = 0x00
CONTROLTYPE_SET_PEER_ID = 0x01
CONTROLTYPE_PING = 0x02
CONTROLTYPE_DISCO = 0x03
CONTROLTYPE_ENABLE_BIG_SEND_WINDOW = 0x04

# Initial sequence number for RELIABLE-type packets.
SEQNUM_INITIAL = 0xFFDC

# Protocol id.
PROTOCOL_ID = 0x4F457403

# No idea.
SER_FMT_VER_HIGHEST_READ = 0x1A

# Supported protocol versions lifted from official client.
MIN_SUPPORTED_PROTOCOL = 0x0d
MAX_SUPPORTED_PROTOCOL = 0x16

class MinetestClientProtocol(object):
    """
    Class for exchanging messages with a Minetest server. Automatically
    processes received messages in a separate thread and performs the initial
    handshake when created. Blocks until the handshake is finished.

    TODO: resend unacknowledged messages and process out-of-order packets.
    """
    def __init__(self, host, username, password=''):
        if ':' in host:
            host, port = host.split(':')
            server = (host, int(port))
        else:
            server = (host, 30000)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server = server
        self.seqnum = SEQNUM_INITIAL
        self.peer_id = 0
        self.username = username
        self.password = password

        # Priority channel, not actually implemented in the official server but
        # required for the protocol.
        self.channel = 0
        # Buffer with the messages received, filled by the listener thread.
        self.receive_buffer = Queue()
        # Last sequence number acknowledged by the server.
        self.acked = 0
        # Buffer for SPLIT-type messages, indexed by sequence number.
        self.split_buffers = defaultdict(dict)

        # Send TOSERVER_INIT and start a reliable connection. The order is
        # strange, but imitates the official client.
        self._handshake_start()
        self._start_reliable_connection()

        # Lock until the handshake is completed.
        self.handshake_lock = Semaphore(0)
        # Run listen-and-process asynchronously.
        thread = Thread(target=self._receive_and_process)
        thread.daemon = True
        thread.start()
        self.handshake_lock.acquire()

    def _send(self, packet):
        """ Sends a raw packet, containing only the protocol header. """
        header = pack('>IHB', PROTOCOL_ID, self.peer_id, self.channel)
        self.sock.sendto(header + packet, self.server)
        logging.warn("Sent: "+ str(header + packet))

    def _handshake_start(self):
        """ Sends the first part of the handshake. """
        packet = pack('>HB20s28sHH',
                TOSERVER_INIT_LEGACY, 
                SER_FMT_VER_HIGHEST_READ,
                self.username.encode('utf-8'), 
                self.password.encode('utf-8'),
                MIN_SUPPORTED_PROTOCOL, 
                MAX_SUPPORTED_PROTOCOL)
        self.send_command(packet)

    def _handshake_end(self):
        """ Sends the second and last part of the handshake. """
        self.send_command(pack('>H', TOSERVER_INIT2))

    def _start_reliable_connection(self):
        """ Starts a reliable connection by sending an empty reliable packet. """
        self.send_command(b'')

    def disconnect(self):
        """ Closes the connection. """
        # The "disconnect" message is just a RELIABLE without sequence number.
        self._send(pack('>H', RELIABLE))

    def _send_reliable(self, message):
        """
        Sends a reliable message. This message can be a packet of another
        type, such as CONTROL or ORIGINAL.
        """
        packet = pack('>BH', RELIABLE, self.seqnum & 0xFFFF) + message
        self.seqnum += 1
        self._send(packet)

    def send_command(self, message):
        """ Sends a useful message, such as a place or say command. """
        start = pack('B', ORIGINAL)
        self._send_reliable(start + message)

    def _ack(self, seqnum):
        """ Sends an ack for the given sequence number. """
        self._send(pack('>BBH', CONTROL, CONTROLTYPE_ACK, seqnum))

    def receive_command(self):
        """
        Returns a command message from the server, blocking until one arrives.
        """
        return self.receive_buffer.get()

    def _process_packet(self, packet):
        """
        Processes a packet received. It can be of type
        - CONTROL, used by the protocol to control the connection
        (ack, set_peer_id and ping);
        - RELIABLE in which it requires an ack and contains a further message to
        be processed;
        - ORIGINAL, which designates it's a command and it's put in the receive
        buffer;
        - or SPLIT, used to send large data.
        """
        packet_type, data = packet[0], packet[1:]
        logging.warn("Received packet type:" + str(packet_type))
        logging.warn("Data: " + str(data))


    def _receive_and_process(self):
        """
        Constantly listens for incoming packets and processes them as required.
        """
        while True:
            packet, origin = self.sock.recvfrom(1024)
            header_size = calcsize('>IHB')
            header, data = packet[:header_size], packet[header_size:]
            protocol, peer_id, channel = unpack('>IHB', header)
            assert protocol == PROTOCOL_ID, 'Unexpected protocol.'
            assert peer_id == 0x01, 'Unexpected peer id, should be 1 got {}'.format(peer_id)
            self._process_packet(data)

