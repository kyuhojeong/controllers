#!/usr/bin/env python

"""GroupVPN is an IPOP controller for virtual private network tailored to use
cases where you want to bring together groups of machines into a virtual
network that is logically connected all-to-all. With the GroupVPN controller,
machines that join a group are assigned virtual addresses within an IP subnet,
each node has connectivity to all other nodes in the group, and IP addresses
are not translated."""


REMOTE_IPOP_IPv4 = ""
REMOTE_IPOP_IPv6 = ""
REMOTE_HOST_IPv4 = ""

from ipoplib import *

import random
import subprocess

class GvpnUdpServer(UdpServer):
    def __init__(self, user, password, host, ip4):
        UdpServer.__init__(self, user, password, host, ip4)
        self.idle_peers = {}
        self.user = user # XMPP username
        self.password = password # XMPP Password
        self.host = host # XMPP host
        self.ip4 = ip4
        self.uid = gen_uid(ip4) # SHA-1 hash
        self.vpn_type = "GroupVPN"
        self.ctrl_conn_init()

        self.uid_ip_table = {}
        parts = CONFIG["ip4"].split(".")
        ip_prefix = parts[0] + "." + parts[1] + "."
        # Populating the uid_ip_table with all the IPv4 addresses
        # and the corresponding UIDs in the /16 subnet
        for i in range(0, 255):
            for j in range(0, 255):
                ip = ip_prefix + str(i) + "." + str(j)
                uid = gen_uid(ip)
                self.uid_ip_table[uid] = ip

        if CONFIG["icc"]:
            self.inter_controller_conn() # UDP Server for Inter Controller Connection
        
        if CONFIG["switchmode"]:
            self.arp_table = {}

        # Ignore the network interfaces in the list
        if "network_ignore_list" in CONFIG:
            logging.debug("network ignore list")
            make_call(self.sock, m="set_network_ignore_list",\
                             network_ignore_list=CONFIG["network_ignore_list"])


    # Initialize the Controller
    def ctrl_conn_init(self):
        do_set_logging(self.sock, CONFIG["tincan_logging"])
        do_set_cb_endpoint(self.sock, self.sock.getsockname()) # Callback endpoint to receive notifications

        if not CONFIG["router_mode"]:
            do_set_local_ip(self.sock, self.uid, self.ip4, gen_ip6(self.uid),
                             CONFIG["ip4_mask"], CONFIG["ip6_mask"],
                             CONFIG["subnet_mask"], CONFIG["switchmode"])
        else:
            do_set_local_ip(self.sock, self.uid, CONFIG["router_ip"],
                           gen_ip6(self.uid), CONFIG["router_ip4_mask"],
                           CONFIG["router_ip6_mask"], CONFIG["subnet_mask"])

        do_register_service(self.sock, self.user, self.password, self.host) # Register to the XMPP server
        do_set_switchmode(self.sock, CONFIG["switchmode"])
        do_set_trimpolicy(self.sock, CONFIG["trim_enabled"])
        do_get_state(self.sock) # Information about the local node
    
    # Create a P2P TinCan link with a peer.
    def create_connection(self, uid, data, nid, sec, cas, ip4):
        do_create_link(self.sock, uid, data, nid, sec, cas)
        if (CONFIG["switchmode"] == 1):
            do_set_remote_ip(self.sock, uid, ip4, gen_ip6(uid))
        else: 
            do_set_remote_ip(self.sock, uid, ip4, gen_ip6(uid))

    def trim_connections(self):
        for k, v in self.peers.iteritems():
            # Trim TinCan link if the peer is offline
            if "fpr" in v and v["status"] == "offline":
                if v["last_time"] > CONFIG["wait_time"] * 2:
                    do_send_msg(self.sock, "send_msg", 1, k,
                                "destroy" + self.ipop_state["_uid"])
                    do_trim_link(self.sock, k)
            # Trim TinCan link if the On Demand Inactive Timeout occurs        
            if CONFIG["on-demand_connection"] and v["status"] == "online": 
                if v["last_active"] + CONFIG["on-demand_inactive_timeout"]\
                                                              < time.time():
                    logging.debug("Inactive, trimming node:{0}".format(k))
                    do_send_msg(self.sock, 1, "send_msg", k,
                                "destroy" + self.ipop_state["_uid"])
                    do_trim_link(self.sock, k)

    # Create an On-Demand connection with an idle peer
    def ondemand_create_connection(self, uid, send_req):
        logging.debug("idle peers {0}".format(self.idle_peers))
        peer = self.idle_peers[uid]
        fpr_len = len(self.ipop_state["_fpr"])
        fpr = peer["data"][:fpr_len]
        cas = peer["data"][fpr_len + 1:]
        ip4 = self.uid_ip_table[peer["uid"]]
        logging.debug("Start mutual creating connection")
        if send_req:
            do_send_msg(self.sock, "send_msg", 1, uid, fpr)
        self.create_connection(peer["uid"], fpr, 1, CONFIG["sec"], cas, ip4)
    
    # Create a TinCan link on request to send the packet
    # received by the controller
    def create_connection_req(self, data):
        version_ihl = struct.unpack('!B', data[54:55])
        version = version_ihl[0] >> 4
        if version == 4:
            s_addr = socket.inet_ntoa(data[66:70])
            d_addr = socket.inet_ntoa(data[70:74])
        elif version == 6:
            s_addr = socket.inet_ntop(socket.AF_INET6, data[62:78])
            d_addr = socket.inet_ntop(socket.AF_INET6, data[78:94])
            # At present, we do not handle ipv6 multicast
            if d_addr.startswith("ff02"):
                return

        uid = gen_uid(d_addr)
        try:
            msg = self.idle_peers[uid]
        except KeyError:
            logging.error("Peer {0} is not logged in".format(d_addr))
            return
        logging.debug("idle_peers[uid] --- {0}".format(msg))
        self.ondemand_create_connection(uid, send_req=True)

    def serve(self):
        # select.select returns a triple of lists of objects that are 
        # ready: subsets of the first three arguments. When the time-out,
        # given as the last argument, is reached without a file descriptor
        # becoming ready, three empty lists are returned.
        socks, _, _ = select.select(self.sock_list, [], [], CONFIG["wait_time"])
        for sock in socks:
            if sock == self.sock or sock == self.sock_svr:
                #---------------------------------------------------------------
                #| offset(byte) |                                              |
                #---------------------------------------------------------------
                #|      0       | ipop version                                 |
                #|      1       | message type                                 |
                #|      2       | Payload (JSON formatted control message)     |
                #---------------------------------------------------------------
                data, addr = sock.recvfrom(CONFIG["buf_size"])
                if data[0] != ipop_ver:
                    logging.debug("ipop version mismatch: tincan:{0} controller"
                                  ":{1}" "".format(data[0].encode("hex"), \
                                   ipop_ver.encode("hex")))
                    sys.exit()
                if data[1] == tincan_control:
                    msg = json.loads(data[2:])
                    logging.debug("recv %s %s" % (addr, data[2:]))
                    msg_type = msg.get("type", None)
                    if msg_type == "echo_request":
                        make_remote_call(self.sock_svr, m_type=tincan_control,\
                          dest_addr=addr[0], dest_port=addr[1], payload=None,\
                          type="echo_reply") # Reply to the echo_request 
                    if msg_type == "local_state":
                        self.ipop_state = msg
                    elif msg_type == "peer_state": 
                        if msg["status"] == "offline" or "stats" not in msg:
                            self.peers[msg["uid"]] = msg
                            self.trigger_conn_request(msg)
                            continue
                        stats = msg["stats"]
                        total_byte = 0
                        global REMOTE_IPOP_IPv4
                        global REMOTE_IPOP_IPv6
                        REMOTE_IPOP_IPv4 = msg["ip4"]
                        REMOTE_IPOP_IPv6 = msg["ip6"]
                        for stat in stats:
                            total_byte += stat["sent_total_bytes"]
                            total_byte += stat["recv_total_bytes"]
                        logging.debug("?? {0} {1} {2}".format(stats[0]["best_conn"], stats[0]["local_type"] , stats[0]["rem_type"]))
                        if stats[0]["best_conn"] and stats[0]["local_type"] == "local" and stats[0]["rem_type"] == "local":
                            ryu_msg = {}
                            ryu_msg["type"] = "tincan_notify"
			    ryu_msg["local_addr"] = stats[0]["local_addr"].split(":")[0]
                            ryu_msg["rem_addr"] = stats[0]["rem_addr"].split(":")[0]
                            # sock.sendto(json.dumps(ryu_msg),("::1", 30001))
                            global REMOTE_HOST_IPv4
                            REMOTE_HOST_IPv4 = stats[0]["rem_addr"].split(":")[0]
                            logging.debug("REMOTE_HOST_IPv4:{0}".format(REMOTE_HOST_IPv4))
                        msg["total_byte"]=total_byte
                        logging.debug("self.peers:{0}".format(self.peers))
                        if not msg["uid"] in self.peers:
                            msg["last_active"]=time.time()
                        elif not "total_byte" in self.peers[msg["uid"]]:
                            msg["last_active"]=time.time()
                        else:
                            if msg["total_byte"] > \
                                         self.peers[msg["uid"]]["total_byte"]:
                                msg["last_active"]=time.time()
                            else:
                                msg["last_active"]=\
                                        self.peers[msg["uid"]]["last_active"]
                        self.peers[msg["uid"]] = msg
    
                    # we ignore connection status notification for now
                    elif msg_type == "con_stat": pass
                    elif msg_type == "con_req": 
                        if CONFIG["on-demand_connection"]: 
                            self.idle_peers[msg["uid"]]=msg
                        else:
                            if self.check_collision(msg_type,msg["uid"]): 
                                continue
                            fpr_len = len(self.ipop_state["_fpr"])
                            fpr = msg["data"][:fpr_len]
                            cas = msg["data"][fpr_len + 1:]
                            ip4 = self.uid_ip_table[msg["uid"]]
                            self.create_connection(msg["uid"], fpr, 1, 
                                                   CONFIG["sec"], cas, ip4)
                    elif msg_type == "con_resp":
                        if self.check_collision(msg_type, msg["uid"]): continue
                        fpr_len = len(self.ipop_state["_fpr"])
                        fpr = msg["data"][:fpr_len]
                        cas = msg["data"][fpr_len + 1:]
                        ip4 = self.uid_ip_table[msg["uid"]]
                        self.create_connection(msg["uid"], fpr, 1, 
                                               CONFIG["sec"], cas, ip4)
    
                    # send message is used as "request for start mutual 
                    # connection"
                    elif msg_type == "send_msg": 
                        if CONFIG["on-demand_connection"]:
                            if msg["data"].startswith("destroy"):
                                do_trim_link(self.sock, msg["uid"])
                            else:
                                self.ondemand_create_connection(msg["uid"], 
                                                                False)
                    elif msg_type == "packet_notify": 
                        if msg["src_port"] == 68:
                            continue #Ignore BOOTP
                        if msg["src_port"] == 5353:
                            continue #Ignore Multicast DNS
                        if msg["src_port"] == 30000:
                            continue #Ignore ICC packet 
                        if msg["nw_proto"] == 17:
                            continue # Let's ignore UDP for the time being
                        #ryu_msg = {}
                        #ryu_msg["type"] = "packet_notify"
                        #ryu_msg["protocol"] = msg["data"].split(',')[0]
                        #msg["remote_ipop_ipv4"] = REMOTE_IPOP_IPv4
                        src_random_port = random.randint(49125, 65535)
                        dst_random_port = random.randint(49125, 65535)
                        msg["remote_host_ipv4"] = REMOTE_HOST_IPv4
                        msg["src_random_port"] = src_random_port 
                        msg["dst_random_port"] = dst_random_port
                        #ryu_msg["src_mac"] = msg["src_mac"]
                        #ryu_msg["dst_mac"] = msg["data"].split(',')[2]
                        #ryu_msg["src_ipv4"] = msg["data"].split(',')[3] 
                        #ryu_msg["dst_ipv4"] = msg["data"].split(',')[4]
                        #logging.debug("Try sending message to {0}".format(REMOTE_IPOP_IPv4))
                        logging.debug("Try sending message to {0}".format("::1 / 30001"))
                        logging.debug("Try sending message to {0}".format(REMOTE_IPOP_IPv6))
                        #msg["type"] = "packet_notify_remote"
                        ret1 = self.cc_sock.sendto(json.dumps(msg), (REMOTE_IPOP_IPv4, 30002))
                        #ret1 = self.cc_sock.sendto(json.dumps(msg), (REMOTE_IPOP_IPv6, 30002))
                        #time.sleep(5)
                        #msg["type"] = "packet_notify_local"
                        ret0 = self.sock.sendto(json.dumps(msg),("::1", 30001))
                        logging.debug("Sent {0} {1} byte".format(ret0, ret1))
                   
                # If a packet that is destined to yet no p2p connection 
                # established node, the packet as a whole is forwarded to 
                # controller
                #|-------------------------------------------------------------|
                #| offset(byte) |                                              |
                #|-------------------------------------------------------------|
                #|      0       | ipop version                                 |
                #|      1       | message type                                 |
                #|      2       | source uid                                   |
                #|     22       | destination uid                              |
                #|     42       | Payload (Ethernet frame)                     |
                #|-------------------------------------------------------------|
                elif data[1] == tincan_packet:
 
                    # Ignore IPv6 packets for log readability. Most of them are
                    # Multicast DNS packets
                    if data[54:56] == "\x86\xdd":
                        continue
                    logging.debug("IP packet forwarded \nversion:{0}\nmsg_type:"
                        "{1}\nsrc_uid:{2}\ndest_uid:{3}\nsrc_mac:{4}\ndst_mac:{"
                        "5}\neth_type:{6}".format(data[0].encode("hex"), \
                        data[1].encode("hex"), data[2:22].encode("hex"), \
                        data[22:42].encode("hex"), data[42:48].encode("hex"),\
                        data[48:54].encode("hex"), data[54:56].encode("hex")))
 
                    if not CONFIG["on-demand_connection"]:
                        continue
                    if len(data) < 16:
                        continue
                    self.create_connection_req(data[2:])
     
                else:
                    logging.error("Unknown type message")
                    logging.debug("{0}".format(data[0:].encode("hex")))
                    sys.exit()

            elif sock == self.cc_sock:
                # Handle the message received by the controller of a peer
                data, addr = sock.recvfrom(CONFIG["buf_size"])
                msg = json.loads(data) 
                logging.debug("recv from icc %s %s" % (addr, data))
                #msg_type = msg.get("type", None)
                #protocol = msg["protocol"] 
                #guest_transport=str(msg["dst_ipv4"]) + ":" + str(msg["dst_port"])
                #dport = msg["random_port"]
                #if msg_type == "packet_notify":
                #    p=subprocess.Popen(["iptables", "-t", "nat", "-L", "PREROUTING"], stdout=subprocess.PIPE)
                #    pp=p.communicate()
                #    ppp = pp[0].split("\n")
                #    if len(ppp) > 10:
                #        continue
                #    p=subprocess.Popen(["iptables", "-t", "nat", "-A", 
                #      "PREROUTING", "-i", "eth0", "-p", protocol, "--dport", 
                #      str(dport), "-j", "DNAT", "--to", guest_transport], 
                #      stdout=subprocess.PIPE)
                #    logging.debug("port forwarding rule is added")
                #self.icc_packet_handle(addr, data)
                
            else:
                logging.error("Unknown type socket")
                sys.exit()
    
def main():
    parse_config()
    server = GvpnUdpServer(CONFIG["xmpp_username"], CONFIG["xmpp_password"],
                       CONFIG["xmpp_host"], CONFIG["ip4"])
    set_global_variable_server(server)
    if CONFIG["stat_report"]:
        server.report() # Report the status of the node to the configured stat_server
    last_time = time.time()
    while True:
        server.serve()
        time_diff = time.time() - last_time
        if time_diff > CONFIG["wait_time"]:
            server.trim_connections()
            do_get_state(server.sock)
            last_time = time.time()

if __name__ == "__main__":
    main()

