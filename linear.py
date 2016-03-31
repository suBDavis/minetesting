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

#Example intro message legacy TOSERVER_INIT_LEGACY
    # 0x0000:  4500 005b 0bbf 4000 4011 30d1 7f00 0001
    # 0x0010:  7f00 0001 8682 7530 0047 fe5a 
    
    # 4f45 7403     protocol id
    # 0002          sender peer id
    # 01            channel
    
    # 01            packet type original
    # 0010          command type legacy init
    # 1a            SER_FM_VER_HIGHEST_READ 26
    # 61 7364 6600 0000 0000 0000 0000 0000 0000 0000 00                            username[20] //who ever thought this was a good idea?
    # 00 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 00        password[28] //literally terrible
    # 00 0d   min protocol 13
    # 00 1a   max protocol 26

#Example protocol 25 message TOSERVER_INIT
    # 4500 0033 0bc0 4000 4011 30f8 7f00 0001
    # 7f00 0001 8682 7530 001f fe32 
    
    # 4f45 7403         protocol id
    # 0002              sender peer id
    # 01                chanel
    
    # 01                packet type original
    # 0002              command type toserver_init
    # 1a                u8 serialisation version (=SER_FMT_VER_HIGHEST_READ)
    # 00 00             u16 supported network compression modes
    # 00 0d             u16 minimum supported network protocol version
    # 00 1a             u16 maximum supported network protocol version
    # 00 04 61 73 64 66 std::string player name (length u16) + string

#Example server response auth TOCLIENT_HELLO
    # 0x0000:  4500 0038 0bc1 4000 4011 30f2 7f00 0001
    # 0x0010:  7f00 0001 7530 8682 0024 fe37 
    
    # 4f45 7403
    # 0001                  #peer id
    # 00                    #channel
    
    # 03                    #type reliable
    # ffdd                  #reliable counter
    
    # 01                    #packet type original
    # 0002                  #the hello command type (server sends u8 types while client sents u16, which is bullshit)
    # 1a                    u8 deployed serialisation version
    # 0000                  u16 deployed network compression mode
    # 001a                  u16 deployed protocol version
    # 0000 0002             u32 supported auth methods
    # 00 04 61 73 64 66     std::string username that should be used for legacy hash (for proper casing)

#Client response 
    # 0x0000:  4500 0027 0bc2 4000 4011 3102 7f00 0001
    # 0x0010:  7f00 0001 8682 7530 0013 fe26 
    
    # 4f45 7403             #protocol id
    # 0002                  #peer id client
    # 00                    #channel 0
    
    # 00                    #packet type control
    # 00                    #control-subtype ack
    # ff dd                 #counter ack

#Client begins negotiating authentication TOSERVER_SRP_BYTES_A
    # 0x0000:  4500 012c 0bc3 4000 4011 2ffc 7f00 0001
    # 0x0010:  7f00 0001 8682 7530 0118 ff2b 

    # 4f45 7403             #protocol id
    # 0002                  #peer id
    # 01                    #channel 1
    
    # 03                    #packet type reliable
    # ffdc                  #reiable counter set
    
    # 01                    #packet type oritingal
    # 0051                  #CLIENT SAYS TOSERVER_SRP_BYTES_A
    # 01 00                 #strlen 256
    # 49 bcde 3588                              A
    # a878 2fbb 54e0 4f5f abe5 acf3 929b c6dc   A
    # dae3 fbed a1bc 9a01 4d89 3a08 6d53 7f6f   A
    # 7008 0da0 705d 5d33 54bd 4bb6 8033 8de6   A
    # 9819 e229 f708 b925 c3c3 1368 42a0 8ac7   A
    # 1dc8 a948 13f7 0c09 0500 bc73 9fbe 5b6f   A
    # f486 45bd e968 60d1 98b3 28f3 c3cc 8d75   A
    # 4cb2 76b9 5aaa 7828 a7e4 27a2 3114 9926   A
    # 0a7a b58a c41a fe87 ede7 b751 ff06 cd63   A
    # 342d b806 9343 bfaa b5bc 483a ba45 cf0d   A
    # ef1f b807 d053 3a50 daa1 1f9b f170 2d18   .
    # 0269 573a 2fd0 1762 3640 c2e9 e3b3 6a27   .
    # b698 ba36 a9e5 fb53 34e2 7ec9 1e3d 6230   .
    # 4f66 36b2 d7dc ed0f 74f7 9e86 d744 251c   .
    # fc58 6e94 edf6 5e6c 26e3 4b34 bfc4 84e2   .
    # d665 cdd9 717b c7ca 9999 16a1 cccf 11ff   .
    # 7baa a0ab 960a 6227 eb75 bd               A
    # 01                    # u8 current login based on the password

#Server ack

    # 4500 0027 0bc4 4000 4011 3100 7f00 0001
    # 7f00 0001 7530 8682 0013 fe26 
    # 4f45 7403             #protocol id
    # 0001                  #peer id server
    # 01                    #channel 1
    
    # 00                    #packet type control
    # 00                    #control type
    # ff dc                 #ack counter

#Server long auth reply 1 TOCLIENT_SRP_BYTES_S_B

    # 4500 013d 0bc5 4000 4011 2fe9 7f00 0001
    # 7f00 0001 7530 8682 0129 ff3c 
    # 4f45 7403             #protocol id
    # 0001                  #peer id server
    # 00                    #channel 0 s
    
    # 03                    #packet type reliable
    # ffde                  #server sets reliable counter now
    
    # 01                    #packet type original
    # 00 60                 #TOCLIENT_SRP_BYTES_S_B
    # 00 10                 #string length - bytes_s 16
    # ae 5a4d 00b6                      bytes_s
    # 2d69 901c 720c b63a fc78 d0       bytes_s
    # 01 00                 #string length - bytes_B
    # a0 fc21               #rest of the message is B
    # d966 a5f6 70d4 6b34 3b71 740f bea8 9049
    # 57a2 2eac 85c6 e9f4 212a 2a8e b632 0dc3
    # 4f9c 3809 e0fd 9641 7144 76ca e025 5b12
    # 5ab8 de3a 1def d97d c4c2 4f8d 4104 79ad
    # 8ac9 6253 3b57 7d00 533b 807b c3fd 0727
    # d9e3 56fc d8c0 170e aacf b241 84b4 7a76
    # 943d d734 4663 1bf6 c345 9d6d 9dc9 a47f
    # 609e 136f fa5e 52aa 61e4 8893 9d63 c618
    # a79a 9266 c900 a9bd 4859 4de9 c928 24e1
    # daf0 69bd 67a7 312d ac5e de6d 73b3 8202
    # 6000 dc2f 2b97 eda6 26ed 808f 08c8 d47d
    # bd6c 3a35 5626 db28 135a 073b f6a5 11e6
    # cb07 4d96 780c bde2 2673 907e e4f8 c590
    # 620e 132c f1a7 bd74 4428 0526 7d6a 11bd
    # 7112 744f d468 17ae 9751 c6a4 b194 c59f
    # 0126 09af a69b 000f ae94 1e8d 8b

#Client ack
    # 4500 0027 0bc6 4000 4011 30fe 7f00 0001
    # 7f00 0001 8682 7530 0013 fe26 
    # 4f45 7403             # protocol id
    # 0002                  # peer id
    # 00                    # channel id 0
    # 00                    # packet id control 
    # 00                    # control id ack
    # ff de                 # reliable number ack

# Client auth response TOSERVER_SRP_BYTES_M
    # 4500 004b 0bc7 4000 4011 30d9 7f00 0001
    # 7f00 0001 8682 7530 0037 fe4a 
    # 4f45 7403             # protocol id
    # 0002                  # peer id client
    # 01                    # channel id 1
    
    # 03                    # reliable packet type
    # ffdd                  # set counter back to ffdd for some fucking reason
    
    # 01                    # original packet type
    # 00 52                 # TOSERVER_SRP_BYTES_M
    # 00 20                 # 32 byte string BYTES_M
    # 5c 779e 16bc
    # 8915 7763 42d6 87e3 c999 b816 ef35 fe78
    # 1cd4 f139 b1bc 3372 520e a9

#Server acks the counter..  gonna stop decoding ack messages now
#Server reply TOCLIENT_AUTH_ACCEPT
    # 4500 0045 0bc8 4000 4011 30de 7f00 0001
    # 7f00 0001 7530 8682 0031 fe44 
    # 4f45 7403             # protocol id
    # 0001                  # peer id server
    # 00                    # channel id
    
    # 03                    # reliable type
    # ffdf                  # set counter 
    
    # 01                    # original type
    # 00 03                 # TOCLIENT_AUTH_ACCEPT
    # 00 0000 0000 0000 0000 0000 006d da12 1d  # v3s16 players position + v3f(0, BS/2, 0)
    # 6a efe2 95            # map seet
    # 00 0000 64            # recommended send interval f1000
    # 00 0000 02            # supported auth methods for sudo mode

#Client acks the server counter update

# Client says TOSERVER_INIT2
    # 4500 0029 0bcc 4000 4011 30f6 7f00 0001
    # 7f00 0001 8682 7530 0015 fe28 
    # 4f45 7403             # proto id
    # 0002                  # peer id
    # 01                    # channel id
    
    # 03                    # reliable packet
    # ffde                  # update counter
    
    # 01                    # original type
    # 00 11                 # TOSERVER_INIT2

# Server acks the counter update

# Server says... TOCLIENT MOVEMENT
    # 4500 0059 0bcd 4000 4011 30c5 7f00 0001
    # 7f00 0001 7530 8682 0045 fe58 
    # 4f45 7403             # proto id
    # 0001                  # peer id server
    # 00                    # channel id 0
    
    # 03                    # reliable type
    # ffe0                  # update counter

    # 01                    # original type
    # 00 45                 # TOCLIENT_MOVEMENT
    
    # DATA::
        # f1000 movement_acceleration_default
        # f1000 movement_acceleration_air
        # f1000 movement_acceleration_fast
        # f1000 movement_speed_walk
        # f1000 movement_speed_crouch
        # f1000 movement_speed_fast
        # f1000 movement_speed_climb
        # f1000 movement_speed_jump
        # f1000 movement_liquid_fluidity
        # f1000 movement_liquid_fluidity_smooth
        # f1000 movement_liquid_sink
        # f1000 movement_gravity

    # EXAMPLES::
    # 00 000b b8            f1000 movement_acceleration_default
    # 00 0007 d0            f1000 movement_acceleration_air
    # 00 0027 10            f1000 movement_acceleration_fast
    # 00 000f a0            f1000 movement_speed_walk
    # 00 0005 46            ...
    # 00 004e 20            
    # 00 0007 d0
    # 00 0019 64
    # 00 0003 e8
    # 00 0001 f4
    # 00 0027 10
    # 00 0026 52

#A very large prime - 2048bit group
AUTH_PRIME="""
AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294
3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D
CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB
D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74
7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A
436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D
5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73
03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6
94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F
9E4AFF73
"""

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

