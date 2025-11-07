#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (c) 2020 Thierry GAUTIER, Wabtec (based on plc.py)
#
"""Establish all what is needed to communicate with a TGV 2020 DCU"""
import logging
import socket
import struct
from scapy import all as scapy_all
import os


from thirdparty.scapy_cip_enip.cip import CIP, CIP_Path, CIP_ReqConnectionManager, \
    CIP_MultipleServicePacket, CIP_ReqForwardOpen, CIP_RespForwardOpen, \
    CIP_ReqForwardClose, CIP_ReqGetAttributeList, CIP_ReqReadOtherTag

from thirdparty.scapy_cip_enip.enip_tcp import ENIP_TCP, ENIP_SendUnitData, ENIP_SendUnitData_Item, \
    ENIP_ConnectionAddress, ENIP_ConnectionPacket, ENIP_RegisterSession, ENIP_SendRRData

from thirdparty.scapy_cip_enip.enip_udp import ENIP_UDP,ENIP_UDP_Item,ENIP_UDP_SequencedAddress,CIP_IO

# Global switch to make it easy to test without sending anything
NO_NETWORK = False

logger = logging.getLogger(__name__)

# Create log directory if it doesn't exist
log_dir = "./log"
os.makedirs(log_dir, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='./log/app.log'
)
    
class Client(object):
    
    """Handle all the state of an Ethernet/IP session with a RER NG project"""
    def __init__(self,
                 IPAddr='10.0.1.1',
                 MulticastGroupIPaddr='239.192.1.3'):

        self.PortEtherNetIPExplicitMessage = 44818 #TCP and UDP
        self.PortEtherNetIPImplicitMessageIO = 2222 #TCP and UDP
        self.ot_connection_param = None
        self.to_connection_param = None
        self.logger = logging.getLogger(self.__class__.__name__)

        """ create two IP connection,
            - first:to manage CIP unicast of DCU TGV2020 (TCP and UDP) ,
            - second:to manage CIP multicast frame (224.0.0.0/4 RFC5771) only UDP due to multicast"""
        if not NO_NETWORK:
            #open connection with DCU 
            try:
                self.Sock = socket.create_connection((IPAddr, self.PortEtherNetIPExplicitMessage))
            except socket.error as exc:
                logger.warn("socket error: %s", exc)
                logger.warn("Continuing without sending anything")
                self.Sock = None

            #open connection to the multicast group
            try:
                # Create the socket
                self.MulticastSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                # Bind to the server address
                self.MulticastSock.bind(('',self.PortEtherNetIPImplicitMessageIO))

                # Tell the operating system to add the socket to the multicast group
                # on all interfaces.
                group = socket.inet_aton(MulticastGroupIPaddr)
                mreq = struct.pack('4sL', group, socket.INADDR_ANY)
                self.MulticastSock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except:
                logger.warn("Not possible to manage multicast group ip address")
                self.MulticastSock = None

            #open connection with DCU TODO
            try:
                self.Sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.Sock1.connect((IPAddr, self.PortEtherNetIPImplicitMessageIO))
            except socket.error as exc:
                logger.warn("socket error: %s", exc)
                logger.warn("Continuing without sending anything --")
                self.Sock1 = None
        else:
            self.Sock = None
            self.MulticastSock = None
            self.Sock1 = None
        
        self.session_id = 0
        self.enip_connection_id_OT = 0 #required for CIP IO O->T
        self.enip_connection_id_TO = 0 #required for CIP IO T->O
        self.sequence_unit_cip = 1
        self.sequence_CIP_IO = 1

        # Open an Ethernet/IP session
        sessionpkt = ENIP_TCP() / ENIP_RegisterSession()
        if self.Sock is not None:
            self.Sock.send(bytes(sessionpkt))
            reply_pkt = self.recv_enippkt()
            self.session_id = reply_pkt.session



    def close(self):
        """Close all sockets open during the init"""
        self.Sock.close()
        if self.MulticastSock:
            self.MulticastSock.close()
        self.Sock1.close()
        

    @property
    def connected(self):
        return True if self.Sock else False

    def send_rr_cip(self, cippkt):
        """Send a CIP packet over the TCP connection as an ENIP Req/Rep Data"""
        enippkt = ENIP_TCP(session=self.session_id)
        enippkt /= ENIP_SendRRData(items=[
            ENIP_SendUnitData_Item(type_id=0),
            ENIP_SendUnitData_Item() / cippkt
        ])
        if self.Sock is not None:
            self.Sock.send(bytes(enippkt))

    def send_rr_cm_cip(self, cippkt):
        """Encapsulate the CIP packet into a ConnectionManager packet"""
        cipcm_msg = [cippkt]
        cippkt = CIP(path=CIP_Path.make(class_id=6, instance_id=1))
        cippkt /= CIP_ReqConnectionManager(message=cipcm_msg)
        self.send_rr_cip(cippkt)

    def send_rr_mr_cip(self, cippkt):
        """Encapsulate the CIP packet into a MultipleServicePacket to MessageRouter"""
        cipcm_msg = [cippkt]
        cippkt = CIP(path=CIP_Path(wordsize=2, path=b'\x20\x02\x24\x01'))
        cippkt /= CIP_MultipleServicePacket(packets=cipcm_msg)
        self.send_rr_cip(cippkt)

    def send_unit_cip(self, cippkt):
        """Send a CIP packet over the TCP connection as an ENIP Unit Data"""
        enippkt = ENIP_TCP(session=self.session_id)
        enippkt /= ENIP_SendUnitData(items=[
            ENIP_SendUnitData_Item() / ENIP_ConnectionAddress(connection_id=self.enip_connection_id_OT),
            ENIP_SendUnitData_Item() / ENIP_ConnectionPacket(sequence=self.sequence_unit_cip) / cippkt
        ])
        self.sequence_unit_cip += 1
        if self.Sock is not None:
            self.Sock.send(bytes(enippkt))

    def recv_enippkt(self):
        """Receive an ENIP packet from the TCP socket"""
        self.logger.info("TGV2020: recv_enippkt executing")
        if self.Sock is None:
            self.logger.warning("TGV2020: recv_enippkt: self.sock is None")
            return
        pktbytes = self.Sock.recv(2000)
        pkt = ENIP_TCP(pktbytes)
        self.logger.info("TGV2020: recv_enippkt: returning enip_tcp packet received")
        return pkt

    def recv_UDP_ENIP_CIP_IO(self,DEBUG=bool(False),Timeout=0):
        """receive cyclic mulicast CIP IO like <AS_DCUi_MPU_DATA>"""
        
        self.logger.info("TGV2020: recv_UDP_ENIP_CIP_IO executing")
        
        if self.MulticastSock is None:
            self.logger.warning("TGV2020: recv_UDP_ENIP_CIP_IO: self.MulticastSock is None")
            return None
        
        #fix timeout
        self.MulticastSock.settimeout(Timeout)
        self.logger.info("TGV2020: recv_UDP_ENIP_CIP_IO: Multicast timeout set")
        
        #wait CIP IO frame during Timeout
        try:
            (pktbytes, address) = self.MulticastSock.recvfrom(2000)

            #extract ethernet/IP part
            pkt_udp = ENIP_UDP(pktbytes)

            if(DEBUG):
                pkt_udp.show()

            #extract CIP IO part
            pkgCIP_IO = CIP_IO(pkt_udp.items[1].payload.load)

            if(DEBUG):
                pkgCIP_IO.show()

            self.logger.info("TGV2020: recv_UDP_ENIP_CIP_IO: CIP_IO packet is returned")
            return pkgCIP_IO

        except:
            self.logger.warning("TGV2020: recv_UDP_ENIP_CIP_IO: NO CIP_IO packet is returned")
            #self.MulticastSock.close()
            return None


    def send_UDP_ENIP_CIP_IO(self,CIP_Sequence_Count=0,Header=0,AppData=None):
        """send cyclic unicast CIP IO like <AS_MPU_DCUi_DATA>"""
        self.logger.info("TGV2020: send_UDP_ENIP_CIP_IO executing")
        enippkt = ENIP_UDP(count=2,items=[
            ENIP_UDP_Item(type_id="Sequenced_Address",length=8) / ENIP_UDP_SequencedAddress(connection_id=self.enip_connection_id_OT, sequence=self.sequence_CIP_IO),
            ENIP_UDP_Item(type_id="Connected_Data_Item",length=len(AppData)+len(CIP_IO()))
        ])
        #add CIP IO part
        enippkt /= CIP_IO(CIP_Sequence_Count=CIP_Sequence_Count,Header=Header)
        
        #add data application part of the project
        enippkt /= AppData

        self.sequence_CIP_IO += 1
        self.logger.info(f"TGV2020: send_UDP_ENIP_CIP_IO: sequence_CIP_IO {self.sequence_CIP_IO}")
        if self.Sock1 is not None:
            self.logger.info("TGV2020: send_UDP_ENIP_CIP_IO: Sending UDP_ENIP_CIP_IO through socket")
            self.Sock1.send(bytes(enippkt))
        else:
            self.logger.warning("TGV2020: send_UDP_ENIP_CIP_IO: Socket error: failed to send UDP_ENIP_CIP_IO")

    def forward_open(self):
        """Send a forward open request"""
        self.logger.info("TGV2020: forward_open executing")
        cippkt = CIP(service=0x54, path=CIP_Path(wordsize=2, path=b'\x20\x06\x24\x01'))
        cippkt /= CIP_ReqForwardOpen(connection_path_size=9, connection_path=b"\x34\x04\x00\x00\x00\x00\x00\x00\x00\x00\x20\x04\x24\x01\x2C\x65\x2C\x64",
                                     OT_connection_param=self.ot_connection_param, TO_connection_param=self.to_connection_param)
        self.send_rr_cip(cippkt)
        resppkt = self.recv_enippkt()
        if self.Sock is None:
            self.logger.warning("TGV2020: forward_open: Socket Error: Socket was found close")
            return
        cippkt = resppkt[CIP]
    
        if cippkt.status[0].status != 0:
            logger.error("Failed to Forward Open CIP connection: %r", cippkt.status[0])
            return False
        assert isinstance(cippkt.payload, CIP_RespForwardOpen)
        self.enip_connection_id_OT = cippkt.payload.OT_network_connection_id
        self.enip_connection_id_TO = cippkt.payload.TO_network_connection_id
        return True

    def forward_close(self):
        """Send a forward close request"""
        cippkt = CIP(service=0x4e, path=CIP_Path(wordsize=2, path=b'\x20\x06\x24\x01'))
        cippkt /= CIP_ReqForwardClose(connection_path_size=9, connection_path=b"\x34\x04\x00\x00\x00\x00\x00\x00\x00\x00\x20\x04\x24\x01\x2C\x65\x2C\x64")
        self.send_rr_cip(cippkt)
        if self.Sock is None:
            return
        resppkt = self.recv_enippkt()
        cippkt = resppkt[CIP]
        
        if cippkt.status[0].status != 0:
            logger.error("Failed to Forward Close CIP connection: %r", cippkt.status[0])
            return False
        
        return True

    def get_attribute(self, class_id, instance, attr):
        """Get an attribute for the specified class/instance/attr path"""
        # Get_Attribute_Single does not seem to work properly
        # path = CIP_Path.make(class_id=class_id, instance_id=instance, attribute_id=attr)
        # cippkt = CIP(service=0x0e, path=path)  # Get_Attribute_Single
        path = CIP_Path.make(class_id=class_id, instance_id=instance)
        cippkt = CIP(path=path) / CIP_ReqGetAttributeList(attrs=[attr])
        self.send_rr_cm_cip(cippkt)
        if self.Sock is None:
            return
        resppkt = self.recv_enippkt()
        cippkt = resppkt[CIP]
        
        if cippkt.status[0].status != 0:
            logger.error("CIP get attribute error: %r", cippkt.status[0])
            return
        resp_getattrlist = bytes(cippkt.payload)
        assert resp_getattrlist[:2] == b'\x01\x00'  # Attribute count must be 1
        assert struct.unpack('<H', resp_getattrlist[2:4])[0] == attr  # First attribute
        assert resp_getattrlist[4:6] == b'\x00\x00'  # Status
        return resp_getattrlist[6:]

    def set_attribute(self, class_id, instance, attr, value):
        """Set the value of attribute class/instance/attr"""
        path = CIP_Path.make(class_id=class_id, instance_id=instance)
        # User CIP service 4: Set_Attribute_List
        cippkt = CIP(service=4, path=path) / scapy_all.Raw(load=struct.pack('<HH', 1, attr) + value)
        self.send_rr_cm_cip(cippkt)
        if self.Sock is None:
            return
        resppkt = self.recv_enippkt()
        cippkt = resppkt[CIP]
        
        if cippkt.status[0].status != 0:
            logger.error("CIP set attribute error: %r", cippkt.status[0])
            return False
        return True

    def get_list_of_instances(self, class_id):
        """Use CIP service 0x4b to get a list of instances of the specified class"""
        start_instance = 0
        inst_list = []
        while True:
            cippkt = CIP(service=0x4b, path=CIP_Path.make(class_id=class_id, instance_id=start_instance))
            self.send_rr_cm_cip(cippkt)
            if self.Sock is None:
                return
            resppkt = self.recv_enippkt()

            # Decode a list of 32-bit integers
            data = bytes(resppkt[CIP].payload)
            for i in range(0, len(data), 4):
                inst_list.append(struct.unpack('<I', data[i:i + 4])[0])
            
            cipstatus = resppkt[CIP].status[0].status
            if cipstatus == 0:
                return inst_list
            elif cipstatus == 6:
                # Partial response, query again from the next instance
                start_instance = inst_list[-1] + 1
            else:
                logger.error("Error in Get Instance List response: %r", resppkt[CIP].status[0])
                return

    def read_full_tag(self, class_id, instance_id, total_size):
        """Read the content of a tag which can be quite big"""
        data_chunks = []
        offset = 0
        remaining_size = total_size

        while remaining_size > 0:
            cippkt = CIP(service=0x4c, path=CIP_Path.make(class_id=class_id, instance_id=instance_id))
            cippkt /= CIP_ReqReadOtherTag(start=offset, length=remaining_size)
            self.send_rr_cm_cip(cippkt)
            if self.Sock is None:
                return
            resppkt = self.recv_enippkt()
            
            cipstatus = resppkt[CIP].status[0].status
            received_data = bytes(resppkt[CIP].payload)
            if cipstatus == 0:
                # Success
                assert len(received_data) == remaining_size
            elif cipstatus == 6 and len(received_data) > 0:
                # Partial response (size too big)
                pass
            else:
                logger.error("Error in Read Tag response: %r", resppkt[CIP].status[0])
                return

            # Remember the chunk and continue
            data_chunks.append(received_data)
            offset += len(received_data)
            remaining_size -= len(received_data)
            
        return b''.join(data_chunks)

    @staticmethod
    def attr_format(attrval):
        """Format an attribute value to be displayed to a human"""
        attr_bytes = bytearray(attrval)
        if len(attrval) == 1:
            # 1-byte integer
            return hex(struct.unpack('B', attrval)[0])
        elif len(attrval) == 2:
            # 2-byte integer
            return hex(struct.unpack('<H', attrval)[0])
        elif len(attrval) == 4:
            # 4-byte integer
            return hex(struct.unpack('<I', attrval)[0])
        elif all(b == 0 for b in attr_bytes):
            # a series of zeros
            return '[{} zeros]'.format(len(attrval))
        # format in hexadecimal the content of attrval
        return ' '.join('{:02x}'.format(b) for b in attr_bytes)




