#First thing client does: sends an empty reliable message
    # 4500 0029 0bb3 4000 4011 310f 7f00 0001
    # 7f00 0001 8682 7530 0015 fe28 
    
    # 4f45 7403         protocol id
    # 0000              peer id (unset)
    # 00                channel
    
    # 03                reliable type
    # ffdc              reliable set counter
    
    # 01                original type
    # 00 00             this is not a command type

#Server replies with a set peer id
    # 4500 002a 0bb4 4000 4011 310d 7f00 0001
    # 7f00 0001 7530 8682 0016 fe29 
    # 4f45 7403         proto id
    # 0001              peer id of server is always u16 0x0001
    # 00                channel id
    # 03                reliable type
    # ffdc              reliable set counter
    
    # 00                control type
    # 01                CONTROLTYPE_SET_PEER_ID
    # 0002              peer id is 2

# Server does a normal ack of the clent's first reliable upgrade.

# Client sets again, with CONTROLTYPE_ENABLE_BIG_SEND_WINDOW = 0x04
    # 4500 0028 0bb6 4000 4011 310d 7f00 0001
    # 7f00 0001 8682 7530 0014 fe27 
    # 4f45 7403         proto id
    # 0002              peer id
    # 00                channel id
    # 03                reliable type
    # ffdd              reliable set
    # 0004              controltype_enable_big_send_window

#Client ack server set of ffdc
#Server ack client set of ffdd

# ---------------------------------------------
# Ready to begin the protocol 25 auth handshake
# ---------------------------------------------

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