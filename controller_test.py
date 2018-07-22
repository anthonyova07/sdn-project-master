import logging
import requests
import hashlib
import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp

_ipaddr='http://127.0.0.1:'
_ipaddr_port=8080
LOG = logging.getLogger('DynamicAccess')
LOG.setLevel(logging.INFO)
logging.basicConfig()

#action fields
_OUTPUT="OUTPUT"
_SETFIELD="SET_FIELD"
_field_eth_dst="eth_dst"
_field_ipv4_dst="ipv4_dst"
_field_eth_src="eth_src"
_field_ipv4_src="ipv4_src"