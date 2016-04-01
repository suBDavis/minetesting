#Create a linear version that completes auth.  Deal with other shit later.
import socket
from struct import pack, unpack, calcsize
from binascii import hexlify
from threading import Thread, Semaphore
from queue import Queue
from collections import defaultdict
import math
import time
import logging

#All Non-obselete Server->Client protocols
TOCLIENT_HELLO = 0x02
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
SUPPORTED_COMPRESSION_MODES = 0x00

# Supported protocol versions lifted from official client.
MIN_SUPPORTED_PROTOCOL = 0x0D
MAX_SUPPORTED_PROTOCOL = 0x1A

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
        self.talk_channel = 1
        self.ack_channel = 0
        self.channel = 0

        # keep a counter so we only ever send a peer id empty once
        self.send_counter = 0
        # Buffer with the messages received, filled by the listener thread.
        self.receive_buffer = Queue()
        # Last sequence number acknowledged by the server.
        self.acked = 0
        # Buffer for SPLIT-type messages, indexed by sequence number.
        self.split_buffers = defaultdict(dict)

        #ack queue
        self.ack_queue = []
        # self.handshake_next_ack = False

        # Send TOSERVER_INIT and start a reliable connection. The order is
        # strange, but imitates the official client.
        # self._start_reliable_connection()

        # Lock until the handshake is completed.
        self.handshake_lock = Semaphore(0)
        # Run listen-and-process asynchronously.
        # thread = Thread(target=self._receive_and_process)
        # thread.daemon = True
        # thread.start()
        # self.handshake_lock.acquire()

        self._blocking_handshake()

    def _send(self, packet, channel):
        """ Sends a raw packet, containing only the protocol header. """
        header = pack('>IHB', PROTOCOL_ID, self.peer_id, self.channel)
        self.sock.sendto(header + packet, self.server)
        logging.warn("Sent: "+ str(header + packet))
        self.send_counter += 1

    def _blocking_handshake(self):

        seqnum = SEQNUM_INITIAL

        # 1 Send empty reliable message
        self._start_reliable_connection()
        
        # 2 Wait for server to syn and send mypeer id
        packet = self._blocking_receive_one()
        if packet[0] == RELIABLE:
            seqnum, ctrl_type, ctrl_peer, peer_id = unpack('>HBBH', packet[1])
            self.peer_id = peer_id
            self.seqnum = seqnum
            assert ctrl_peer == CONTROLTYPE_SET_PEER_ID
        logging.warn(packet)

        # 3 Wait for server to ack
        packet = self._blocking_receive_one()
        if packet[0] == CONTROL:
            ctrl_type, seqnum = unpack('>BH', packet[1])
            self.seqnum = 0xFFDD

        # 4 Syn large window request
        self._enable_big_send_window()

        # 5 Ack last syn
        self._ack(seqnum)

        # 6 Wait for server to ack
        packet = self._blocking_receive_one()
        if packet[0] == CONTROL:
            ctrl_type, seqnum = unpack('>BH', packet[1])
            self.seqnum = seqnum

        # 7 Send legacy TOSERVER_INIT_LEGACY
        # 8 Send regular TOSERVER_INIT
        self._handshake_start()

        # 9 Wait for server hello
        packet = self._blocking_receive_one()
        logging.warn(packet)

        # 10 Ack hello

        # 11 SYN TOSERVER_SRP_BYTES_A

        # 12 Wait for server ack

        # 13 Wait for server syn TOCLIENT_SRP_BYTES_S_B

        # 14 Ack last

        # 15 SYN TOSERVER_SRP_BYTES_M

        # 16 Wait for server ack

        # 17 Wait for server TOCLIENT_AUTH_ACCEPT

        # 18 Ack last
        
        # 19 SYN TOSERVER_INIT2

        # 20 Wait for server ack

        # Done - begin reading messages normally

    def _send_channel_1(self, packet):
        """ Sends a raw packet, containing only the protocol header. """
        header = pack('>IHB', PROTOCOL_ID, self.peer_id, self.talk_channel)
        self.sock.sendto(header + packet, self.server)
        logging.warn("Sent: "+ str(header + packet))

    def _handshake_start(self):
        """ Sends the first part of the handshake. """
        
        packet_legacy = pack('>HB20s28sHH',
                TOSERVER_INIT_LEGACY, 
                SER_FMT_VER_HIGHEST_READ,
                self.username.encode('utf-8'), 
                self.password.encode('utf-8'),
                MIN_SUPPORTED_PROTOCOL, 
                MAX_SUPPORTED_PROTOCOL)
        
        # Try to upgrade to protocol 25
        username_length = len(self.username)
        packet = pack('>HBHHHH' + str(username_length) + 's',
            TOSERVER_INIT,
            SER_FMT_VER_HIGHEST_READ,
            SUPPORTED_COMPRESSION_MODES,
            MIN_SUPPORTED_PROTOCOL, 
            MAX_SUPPORTED_PROTOCOL, 
            username_length,
            self.username.encode('utf-8'))

        self._send_channel_1(pack('B', ORIGINAL) + packet_legacy)
        self._send_channel_1(pack('B', ORIGINAL) + packet)

    def _handshake_end(self):
        """ Sends the second and last part of the handshake. """
        self.send_command(pack('>H', TOSERVER_INIT2))

    def _start_reliable_connection(self):
        """ Starts a reliable connection by sending an empty reliable packet. """
        #self.send_command(b'') #client sends this as the command type, so I will too
        packet = pack('>BHBH', RELIABLE, self.seqnum & 0xFFFF, 0x01, 0x0000)
        self._send(packet, self.talk_channel)
        self.seqnum += 1

    def _enable_big_send_window(self):
        self._send_reliable(pack('>H', 4))

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
        self._send(packet, self.talk_channel)

    def send_command(self, message):
        """ Sends a useful message, such as a place or say command. """
        start = pack('B', ORIGINAL)
        self._send_reliable(start + message)

    def _ack(self, seqnum):
        """ Sends an ack for the given sequence number. """
        self._send(pack('>BBH', CONTROL, CONTROLTYPE_ACK, seqnum), self.ack_channel)

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

        # if packet_type == CONTROL:
        #     #We received a control packet.  
        #     #Read the next byte, it contains the control type
        #     control_type = data[0]
        #     if len(data) == 1:
        #         if control_type == CONTROLTYPE_PING:
        #             # we already ack'd
        #             return
        #         elif control_type == CONTROLTYPE_DISCO:
        #             logger.warn("disconnect")
        #             return
        #     #otherwise, the server might have some other data for us
        #     control_type, value = unpack('>BH', data)
        #     if control_type == CONTROLTYPE_ACK:
        #         #Just the server acking the counter.  Don't worry about this.
        #         self.acked = value
        #     elif control_type == CONTROLTYPE_SET_PEER_ID:
        #         self.peer_id = value
        #         #We have a peer id, so we can start handshake now
        #         #but first, ack all the shit you couldn't becayse you were waiting for a peer
        #         for sn in self.ack_queue:
        #             self._ack(sn)
        #         self._enable_big_send_window()
        #         self._handshake_start()
        # elif packet_type == RELIABLE:
        #     seqnum, = unpack('>H', data[:2])
        #     self._ack(seqnum)
        #     self._process_packet(data[2:])
        # elif packet_type == ORIGINAL:
        #     self.receive_buffer.put(data)  


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

    def _blocking_receive_one(self):
        #Takes a callback function calback, which should take one argument
        packet, origin = self.sock.recvfrom(1024)
        header_size = calcsize('>IHB')
        header, data = packet[:header_size], packet[header_size:]
        protocol, peer_id, channel = unpack('>IHB', header)
        assert protocol == PROTOCOL_ID, 'Unexpected protocol.'
        assert peer_id == 0x01, 'Unexpected peer id, should be 1 got {}'.format(peer_id)
        packet_type, packet_data = data[0], data[1:]
        return (packet_type, packet_data)

class MinetestClient(object):
    """
    Class for sending commands to a remote Minetest server. This creates a
    character in the running world, controlled by the methods exposed in this
    class.
    """
    def __init__(self, server='localhost:30000', username='user', password='', on_message=id):
        """
        Creates a new Minetest Client to send remote commands.

        'server' must be in the format 'host:port' or just 'host'.
        'username' is the name of the character on the world.
        'password' is an optional value used when the server is private.
        'on_message' is a function called whenever a chat message arrives.
        """
        logging.info("Starting errything")
        self.protocol = MinetestClientProtocol(server, username, password)

        # We need to constantly listen for server messages to update our
        # position, HP, etc. To avoid blocking the caller we create a new
        # thread to process those messages, and wait until we have a confirmed
        # connection.
        self.access_denied = None
        self.init_lock = Semaphore(0)
        thread = Thread(target=self._receive_and_process)
        thread.daemon = True
        thread.start()
        # Wait until we know our position, otherwise the 'move' method will not
        # work.
        self.init_lock.acquire()

        if self.access_denied is not None:
            raise ValueError('Access denied. Reason: ' + self.access_denied)

        self.on_message = on_message

        # HP is not a critical piece of information for us, so we assume it's full
        # until the server says otherwise.
        self.hp = 20

    def say(self, message):
        """ Sends a global chat message. """
        message = str(message)
        encoded = message.encode('UTF-16BE')
        packet = pack('>HH', TOSERVER_CHAT_MESSAGE, len(message)) + encoded
        self.protocol.send_command(packet)

    def respawn(self):
        """ Resurrects and teleports the dead character. """
        packet = pack('>H', TOSERVER_RESPAWN)
        self.protocol.send_command(packet)

    def damage(self, amount=20):
        """
        Makes the character damage itself. Amount is measured in half-hearts
        and defaults to a complete suicide.
        """
        packet = pack('>HB', TOSERVER_DAMAGE, int(amount))
        self.protocol.send_command(packet)

    def move(self, delta_position=(0,0,0), delta_angle=(0,0), key=0x01):
        """ Moves to a position relative to the player. """
        x = self.position[0] + delta_position[0]
        y = self.position[1] + delta_position[1]
        z = self.position[2] + delta_position[2]
        pitch = self.angle[0] + delta_angle[0]
        yaw = self.angle[1] + delta_angle[1]
        self.teleport(position=(x, y, z), angle=(pitch, yaw), key=key)

    def teleport(self, position=None, speed=(0,0,0), angle=None, key=0x01):
        """ Moves to an absolute position. """
        position = position or self.position
        angle = angle or self.angle

        x, y, z = map(lambda k: int(k*1000), position)
        dx, dy, dz = map(lambda k: int(k*100), speed)
        pitch, yaw = map(lambda k: int(k*100), angle)
        packet = pack('>H3i3i2iI', TOSERVER_PLAYERPOS, x, y, z, dx, dy, dz, pitch, yaw, key)
        self.protocol.send_command(packet)
        self.position = position
        self.angle = angle

    def turn(self, degrees=90):
        """
        Makes the character face a different direction. Amount of degrees can
        be negative.
        """
        new_angle = (self.angle[0], self.angle[1] + degrees)
        self.teleport(angle=new_angle)

    def walk(self, distance=1):
        """
        Moves a number of blocks forward, relative to the direction the
        character is looking.
        """
        dx = distance * math.cos((90 + self.angle[1]) / 180 * math.pi)
        dz = distance * math.sin((90 + self.angle[1]) / 180 * math.pi)
        self.move((dx, 0, dz))

    def disconnect(self):
        """ Disconnects the client, removing the character from the world. """
        self.protocol.disconnect()

    def _receive_and_process(self):
        """
        Receive commands from the server and process them synchronously. Most
        commands are not implemented because we didn't have a need.
        """
        while True:
            packet = self.protocol.receive_command()
            (command_type,), data = unpack('>H', packet[:2]), packet[2:]
            logging.warn("Command type is "  + str(command_type))

            if command_type == TOCLIENT_INIT_LEGACY:
                # No useful info here.
                pass
            elif command_type == TOCLIENT_HELLO:
                (dep_ser_ver, compress_mode, proto_version, auth_methods, uname_len, uname) , uname = unpack('>BHHIH'), data[12:]
            elif command_type == TOCLIENT_MOVE_PLAYER:
                x10000, y10000, z10000, pitch1000, yaw1000 = unpack('>3i2i', data)
                self.position = (x10000/10000, y10000/10000, z10000/10000)
                self.angle = (pitch1000/1000, yaw1000/1000)
                self.init_lock.release()
            elif command_type == TOCLIENT_CHAT_MESSAGE:
                length, bin_message = unpack('>H', data[:2]), data[2:]
                # Length is not matching for some reason.
                #assert len(bin_message) / 2 == length 
                message = bin_message.decode('UTF-16BE')
                self.on_message(message)
            elif command_type == TOCLIENT_DEATHSCREEN:
                self.respawn()
            elif command_type == TOCLIENT_HP:
                self.hp, = unpack('B', data)
            elif command_type == TOCLIENT_INVENTORY_FORMSPEC:
                pass
            elif command_type == TOCLIENT_INVENTORY:
                pass
            elif command_type == TOCLIENT_PRIVILEGES:
                pass
            elif command_type == TOCLIENT_MOVEMENT:
                pass
            elif command_type == TOCLIENT_BREATH:
                pass
            elif command_type == TOCLIENT_DETACHED_INVENTORY:
                pass
            elif command_type == TOCLIENT_TIME_OF_DAY:
                pass
            elif command_type == TOCLIENT_REMOVENODE:
                pass
            elif command_type == TOCLIENT_ADDNODE:
                pass
            elif command_type == TOCLIENT_PLAY_SOUND:
                pass
            elif command_type == TOCLIENT_STOP_SOUND:
                pass
            elif command_type == TOCLIENT_NODEDEF:
                pass
            elif command_type == TOCLIENT_ANNOUNCE_MEDIA:
                pass
            elif command_type == TOCLIENT_ITEMDEF:
                pass
            elif command_type == TOCLIENT_ACCESS_DENIED:
                length, bin_message = unpack('>H', data[:2]), data[2:]
                self.access_denied = bin_message.decode('UTF-16BE')
                self.init_lock.release()
            elif command_type == TOCLIENT_ACCESS_DENIED_LEGACY:
                length, bin_message = unpack('>H', data[:2]), data[2:]
                self.access_denied = bin_message.decode('UTF-16BE')
                logging.warn(self.access_denied)
                self.init_lock.release()
            else:
                print('Unknown command type {}.'.format(hex(command_type)))


if __name__ == '__main__':
    import sys
    import time

    args = sys.argv[1:]
    assert len(args) <= 3, 'Too many arguments, expected no more than 3'
    # Load hostname, username and password from the command line arguments.
    # Defaults to localhost:30000, 'user' and empty password (for public
    # servers).
    client = MinetestClient(*args)
    try:
        # Print chat messages received from other players.
        client.on_message = print
        # Send as chat message any line typed in the standard input.
        while not sys.stdin.closed:
            line = sys.stdin.readline().rstrip()
            client.say(line)
    finally:
        client.protocol.disconnect()