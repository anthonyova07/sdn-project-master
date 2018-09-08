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

_ipaddr='http://10.0.1.8:'
_ipaddr_port=6633
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
_field_in_port="in_phy_port"


#cookie ids
_client1_aa_cookie=1
_client2_aa_cookie=2
_client1_cookie=3
_client2_cookie=4

#table_ids
_access_table_id=1
_redirect_table_id=2

#match fields
_match_dl_type=2048

#flow time set
_forward_idle_timeout=900
_forward_hard_timeout=900


#forward priority set
_forward_priority=1111

#reverse priority set
_reverse_priority=1111

#flag set
_flag_set=1

#_dpid
_dpid=0

serv_type = ['external','authserver']


#using index to get server type like as 0=external,1=authServer
server_ip_list=[]

datapath=None
cookieId=[]

class Begin(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Begin, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
    
    def get_specific_server(self,server_type):
        serv_ttype=serv_type[server_type]
        for server_ip in server_ip_list:
            if server_ip['server_type'] != serv_ttype:
                continue
            else:
                return server_ip
        return None
    
    def has_code(self,string):
        LOG.info("has_code")
        return abs(hash(string)) % (10 ** 6)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        global datapath
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        LOG.info("MSG"+str(msg))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            pkt_arp = pkt.get_protocols(arp.arp)[0]
            LOG.info("Pkt"+str(pkt_arp))
            self._handle_arp(pkt_arp,in_port)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        #self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        '''
        {{src_mac:in_port}} -->mac_to_port[][]
        '''
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
   
    
    def request_post(self,url,data):
        data_json = json.dumps(data)
        print ('JSON being sent - ', data_json)
        headers = {'Content-type': 'application/json'}
        response = requests.post(url, data=data_json, headers=headers)
        LOG.info("_request_post successfully")
         
    def _populate_json(self,*args):
        pass
    
    def json_request_parse(self,obj):
        server_key=["external_port","internal_port","authServer_port"]
        LOG.info("server_key"+str(server_key)) 
        for sv_type in serv_type:
            LOG.info("json_request_parse"+str(sv_type)) 
            for x in server_key:
                LOG.info("json_request_parse"+str(x))
                ex=obj[x[0]]
                inn=obj[x[1]]
                port=obj[x[2]]
                self.create_request(ex=ex,inn=inn,port=port,server_type=sv_type)
        LOG.info("json_request_parse"+str(obj))        
        return


     def create_request(self,ex=None,inn=None,port=None,server_type=None):
        new_request={'ex':ex,'inn':inn,'port':port,'server_type':server_type}
        server_ip_list.append(new_request)
        LOG.info("create_request:"+ex+inn+port+server_type)     

    ##POST http://localhost:8080/stats/flowentry/add
    #(arguments=10
    def add_redirect_forward_flow_byrest(self,dpid,cookie,cookie_mask,table_id,in_port,ipv4_src,ipv4_dst,eth_aa_dst,ipv4_aa_dst,out_aa_port):
        add_dist={}
        add_dist['dpid']=dpid
        add_dist['cookie']=cookie
        add_dist['cookie_mask']=cookie_mask 
        add_dist['table_id']=table_id
        add_dist['idle_timeout']=_forward_idle_timeout
        add_dist['hard_timeout']=_forward_hard_timeout
        add_dist['priority']=_forward_priority
        add_dist['flags']=_flag_set
        add_dist['match']={"in_port":in_port,
                           "dl_type": _match_dl_type,
                           "ipv4_src":ipv4_src,
                           "ipv4_dst":ipv4_dst
                        }
        add_dist['actions']=[
                             {
                              "type":_SETFIELD,
                              "field": _field_eth_dst,
                              "value":eth_aa_dst
                              },
                              {
                               "type":_SETFIELD,
                               "field":_field_ipv4_dst,
                               "value":ipv4_aa_dst
                               },
                             {
                              "type":_OUTPUT,
                              "port": out_aa_port
                              }
                             ]
        LOG.info("_add_redirect_flow_byrest_calling_rest_start")
        self.request_post(_ipaddr+str(_ipaddr_port)+'/stats/flowentry/add', add_dist)
        LOG.info("_add_redirect_flow_byrest_calling_rest_end")
        
    def add_redirect_reverse_flow_byrest(self,dpid,cookie,cookie_mask,table_id,in_port,ipv4_aa_src,ipv4_dst,eth_server_src,ip_server_src,client_out_port):
        add_dist={}
        add_dist['dpid']=dpid
        add_dist['cookie']=cookie
        add_dist['cookie_mask']=cookie_mask 
        add_dist['table_id']=table_id
        add_dist['idle_timeout']=_forward_idle_timeout
        add_dist['hard_timeout']=_forward_hard_timeout
        add_dist['priority']=_forward_priority
        add_dist['flags']=_flag_set
        add_dist['match']={
                           "in_port":in_port,
                           "dl_type": _match_dl_type,
                           "ipv4_src":ipv4_aa_src,
                           "ipv4_dst":ipv4_dst
                           }
        add_dist['actions']=[
                             {
                              "type":_SETFIELD,
                              "field": _field_eth_src,
                              "value":eth_server_src
                              },
                              {
                               "type":_SETFIELD,
                               "field":_field_ipv4_src,
                               "value":ip_server_src
                               },
                             {
                              "type":_OUTPUT,
                              "port": client_out_port
                              }
                             ]
        LOG.info("_add_redirect_flow_byrest_calling_rest_start")
        self.request_post(_ipaddr+str(_ipaddr_port)+'/stats/flowentry/add', add_dist)
        LOG.info("_add_redirect_flow_byrest_calling_rest_end")
        
    def add_provision_flows(self,obj):
        ex=obj['ip_address']
        policy_type=obj['policy_type']       "in_port":in_port,
                           "dl_type": _match_dl_type,
                           "ipv4_src":ipv4_aa_src,
                           "ipv4_dst":ipv4_dst
                           }
        add_dist['actions']=[
                             {
                              "type":_SETFIELD,
                              "field": _field_eth_src,
                              "value":eth_server_src
                              },
                              {
                               "type":_SETFIELD,
                               "field":_field_ipv4_src,
                               "value":ip_server_src
                               },
                             {
                              "type":_OUTPUT,
                              "port": client_out_port
                              }
                             ]
        LOG.info("_add_redirect_flow_byrest_calling_rest_start")
        self.request_post(_ipaddr+str(_ipaddr_port)+'/stats/flowentry/add', add_dist)
        LOG.info("_add_redirect_flow_byrest_calling_rest_end")
        
   
        
    def add_acessprovision_forward_flow_byrest(self,dpid,cookie,cookie_mask,table_id,in_port,ipv4_src_addr,ipv4_dst_aadr,out_port):
        add_dist={}
        add_dist['dpid']=dpid
        add_dist['cookie']=cookie
        add_dist['cookie_mask']=cookie_mask 
        add_dist['table_id']=table_id
        add_dist['idle_timeout']=_forward_idle_timeout
        add_dist['hard_timeout']=_forward_hard_timeout
        add_dist['priority']=_forward_priority
        add_dist['flags']=_flag_set
        add_dist['match']={"in_port":in_port,   
                           "dl_type": _match_dl_type,
                           "ipv4_src":ipv4_src_addr,
                           "ipv4_dst":ipv4_dst_aadr
                           }
        add_dist['actions']=[
                             {
                              "type":_OUTPUT,
                              "port": out_port
                              }
                             ]
        LOG.info("_add_redirect_flow_byrest_calling_rest_start")
        self.request_post(_ipaddr+str(_ipaddr_port)+'/stats/flowentry/add', add_dist)
        LOG.info("_add_redirect_flow_byrest_calling_rest_end")    
        
    def add_acessprovision_reverse_flow_byrest(self,dpid,cookie,cookie_mask,table_id,in_port,ipv4_src_addr,ipv4_dst_aadr,out_port):
        add_dist={}
        add_dist['dpid']=dpid
        add_dist['cookie']=cookie
        add_dist['cookie_mask']=cookie_mask 
        add_dist['table_id']=table_id
        add_dist['idle_timeout']=_forward_idle_timeout
        add_dist['hard_timeout']=_forward_hard_timeout
        add_dist['priority']=_forward_priority
        add_dist['flags']=_flag_set
        add_dist['match']={"in_port":in_port,   
                           "dl_type": _match_dl_type,
                           "ipv4_src":ipv4_src_addr,
                           "ipv4_dst":ipv4_dst_aadr
                                      }
        add_dist['actions']=[
                             {
                              "type":_OUTPUT,
                              "port": out_port
                              }
                             ]
        LOG.info("_add_redirect_flow_byrest_calling_rest_start")
        self.request_post(_ipaddr+str(_ipaddr_port)+'/stats/flowentry/add', add_dist)
        LOG.info("_add_redirect_flow_byrest_calling_rest_end")    
    
    #POST http://localhost:8080/stats/flowentry/delete
    def del_flow_byrest(self,dpid,cookie,cookie_mask,table_id,idle_timeout,hard_timeout,priority,flags,in_port,type_type,port):
        del_dist={}
        del_dist['dpid']=dpid
        del_dist['cookie']=cookie
        #del_dist['cookie_mask']=cookie_mask
        del_dist['table_id']=table_id
        #del_dist['idle_timeout']=idle_timeout
        #del_dist['hard_timeout']=hard_timeout
        #del_dist['priority']=priority
        #del_dist['flags']=flags
        #del_dist['match']={}
        #del_dist['actions']=[]
        LOG.info("_del_redirect_flow_byrest_calling_rest_start")
        self.request_post(_ipaddr+str(_ipaddr_port)+'/stats/flowentry/delete', del_dist)
        LOG.info("_del_redirect_flow_byrest_calling_rest_end")        


