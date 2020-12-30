import nnpy
import struct
import ipaddress
from scapy.all import sniff, get_if_list, Ether, get_if_hwaddr, IP, Raw

import datetime
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI


class RoutingController(object):

    def __init__(self):

        self.topo = Topology(db="topology.db")
        self.controllers = {}
        self.init()

    def init(self):
        self.connect_to_switches()
        self.reset_states()
        self.set_table_defaults()

    def reset_states(self):
        [controller.reset_state() for controller in self.controllers.values()]

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchAPI(thrift_port)

    def set_table_defaults(self):
        for controller in self.controllers.values():
            controller.table_set_default("ipv4_lpm", "drop", [])
            controller.table_set_default("ecmp_group_to_nhop", "drop", [])

    def route(self):

        switch_ecmp_groups = {sw_name:{} for sw_name in self.topo.get_p4switches().keys()}

        for sw_name, controller in self.controllers.items():
            for sw_dst in self.topo.get_p4switches():

                #if its ourselves we create direct connections
                if sw_name == sw_dst:
                    for host in self.topo.get_hosts_connected_to(sw_name):
                        sw_port = self.topo.node_to_node_port_num(sw_name, host)
                        host_ip = self.topo.get_host_ip(host) + "/32"
                        host_mac = self.topo.get_host_mac(host)

                        #add rule
                        print "table_add at {}:".format(sw_name)
                        self.controllers[sw_name].table_add("ipv4_lpm", "set_nhop", [str(host_ip)], [str(host_mac), str(sw_port)])

                #check if there are directly connected hosts
                else:
                    if self.topo.get_hosts_connected_to(sw_dst):
                        paths = self.topo.get_shortest_paths_between_nodes(sw_name, sw_dst)
                        for host in self.topo.get_hosts_connected_to(sw_dst):

                            if len(paths) == 1:
                                next_hop = paths[0][1]

                                host_ip = self.topo.get_host_ip(host) + "/24"
                                sw_port = self.topo.node_to_node_port_num(sw_name, next_hop)
                                dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw_name)

                                #add rule
                                print "table_add at {}:".format(sw_name)
                                self.controllers[sw_name].table_add("ipv4_lpm", "set_nhop", [str(host_ip)],
                                                                    [str(dst_sw_mac), str(sw_port)])

                            elif len(paths) > 1:
                                next_hops = [x[1] for x in paths]
                                dst_macs_ports = [(self.topo.node_to_node_mac(next_hop, sw_name),
                                                   self.topo.node_to_node_port_num(sw_name, next_hop))
                                                  for next_hop in next_hops]
                                host_ip = self.topo.get_host_ip(host) + "/24"

                                #check if the ecmp group already exists. The ecmp group is defined by the number of next
                                #ports used, thus we can use dst_macs_ports as key
                                if switch_ecmp_groups[sw_name].get(tuple(dst_macs_ports), None):
                                    ecmp_group_id = switch_ecmp_groups[sw_name].get(tuple(dst_macs_ports), None)
                                    print "table_add at {}:".format(sw_name)
                                    self.controllers[sw_name].table_add("ipv4_lpm", "ecmp_group", [str(host_ip)],
                                                                        [str(ecmp_group_id), str(len(dst_macs_ports))])

                                #new ecmp group for this switch
                                else:
                                    new_ecmp_group_id = len(switch_ecmp_groups[sw_name]) + 1
                                    switch_ecmp_groups[sw_name][tuple(dst_macs_ports)] = new_ecmp_group_id

                                    #add group
                                    for i, (mac, port) in enumerate(dst_macs_ports):
                                        print "table_add at {}:".format(sw_name)
                                        self.controllers[sw_name].table_add("ecmp_group_to_nhop", "set_nhop",
                                                                            [str(new_ecmp_group_id), str(i)],
                                                                            [str(mac), str(port)])

                                    #add forwarding rule
                                    print "table_add at {}:".format(sw_name)
                                    self.controllers[sw_name].table_add("ipv4_lpm", "ecmp_group", [str(host_ip)],
                                                                        [str(new_ecmp_group_id), str(len(dst_macs_ports))])
    
    
    def main(self):
        self.route()
    
class DigestController():

    def __init__(self, sw_name):

        self.sw_name = sw_name
        self.topo = Topology(db="topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)

    def recv_msg_digest(self, msg):
        f=open("storage.txt", "a")

        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi",
                                                                     msg[:32])
        #print num, len(msg)
        offset =13
        msg = msg[32:]
        for sub_message in range(num):

            random_num,ethertype,ttl,protocol, src,dst = struct.unpack(("!BHBBII"), msg[0:offset])
            #MAC_src=struct.unpack(("!HI"), msg[13:19])
            #MAC_dst=struct.unpack(("!HI"), msg[19:25])
            #print( type(MAC_src))

            print "random number:", random_num,"ethertype",ethertype,"ttl",ttl,"protocole",protocol, "src ip:", str(ipaddress.IPv4Address(src)),"dst ip:", str(ipaddress.IPv4Address(dst))
            y= str(datetime.datetime.now()),"random number:", random_num,"ethertype",hex(ethertype),"ttl",ttl,"protocole",protocol, "src ip:", str(ipaddress.IPv4Address(src)),"dst ip:", str(ipaddress.IPv4Address(dst))

            msg = msg[offset:]

            y=str(y)
            f.write ("********************monitoring on SW1 **********************"+"\n"+y+"\n")

        self.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)
        f.close()
        
        
    
    
    def run_digest_loop(self):

        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        notifications_socket = self.controller.client.bm_mgmt_get_info().notifications_socket
        print "connecting to notification sub2 %s" % notifications_socket
        sub.connect(notifications_socket)
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')

        while True:
            msg = sub.recv()
            self.recv_msg_digest(msg)


    """def run_digest_loop(self):

        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        notifications_socket = self.controller.client.bm_mgmt_get_info().notifications_socket
        print "connecting to notification sub %s" % notifications_socket
        sub.connect(notifications_socket)
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')

        while True:
            
            msg = sub.recv()
            self.recv_msg_digest(msg)
            if(msg!=None):
                break
                


"""

    
def main():
    
    DigestController("s1").run_digest_loop() 
    #print("looooool")
    """DigestController("s6").run_digest_loop2()
    print("hoooooooooooly")"""
                                                                        
    


if __name__ == "__main__":
    controller = RoutingController().main()
    main()
