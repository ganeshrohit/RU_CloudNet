#!/usr/bin/env python3
# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code adapted from the public P4 behavioral model support software.
# https://github.com/p4lang/behavioral-model/

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from p4_mininet import P4Switch, P4Host

import argparse
from time import sleep

parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", required=True)
parser.add_argument('--edge-thrift-ports', help='Comma-delimited thrift ports for edge table updates',
                    type=str, action="store", default="9090,9091,9092")
parser.add_argument('--fabric-thrift-port', help='Thrift server port for fabric table updates',
                    type=int, action="store", default=10101)
parser.add_argument('--num-edges', help='Number of edge switches',
                    type=int, action="store", default=3)
parser.add_argument('--num-hosts', help='Number of hosts to connect to each edge switch',
                    type=int, action="store", default=3)
parser.add_argument('--mode', choices=['l2', 'l3'], type=str, default='l3')
parser.add_argument('--edge_json', help='Path to Edge JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--fabric_json', help='Path to Fabric JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--pcap-dump', help='Dump packets on interfaces to pcap files',
                    action="store_true", required=False, default=False)
parser.add_argument('--enable-debugger', help='Enable debugger (Please ensure debugger support is enabled in behavioral exe, as it is disabled by default)',
                    action="store_true", required=False, default=False)

args = parser.parse_args()

# Experiment-specific host IP addresses:
host_addresses = {
    "h1": "172.16.0.1/24",
    "h2": "192.168.0.2/24",
    "h3": "10.0.0.3/24",
    "h4": "172.16.0.4/24",
    "h5": "192.168.0.5/24",
    "h6": "10.0.0.6/24",
    "h7": "172.16.0.7/24",
    "h8": "192.168.0.8/24",
    "h9": "10.0.0.9/24"
}

class StarTopo(Topo):
    "Dumb-bell topology connected to n < 256 hosts."
    def __init__(self, sw_path, edge_json_path, fabric_json_path, edge_thrift_ports,
                 fabric_thrift_port, pcap_dump, enable_debugger, n, edges, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        # Initialize edge switches first
        edge_switches = []
        for j in range(edges):
            switch_name = 's%d' % (j+1)
            switch = self.addSwitch(switch_name,
                                    sw_path = sw_path,
                                    json_path = edge_json_path,
                                    thrift_port = edge_thrift_ports[j],
                                    pcap_dump = pcap_dump,
                                    enable_debugger = enable_debugger)
            edge_switches.append(switch)
            
        fabric_switch = self.addSwitch('s%d' % (edges + 1),
                                       sw_path = sw_path,
                                       json_path = fabric_json_path,
                                       thrift_port = fabric_thrift_port,
                                       pcap_dump = pcap_dump,
                                       enable_debugger = enable_debugger)

        for edge in range(edges):
            for h in range(n):
                host_index = (edge*n) + h + 1
                host_name  = 'h%d' % host_index
                host = self.addHost(host_name,
                                    ip = host_addresses[host_name],
                                    mac = '00:04:00:00:00:%02x' % host_index)
                self.addLink(host, edge_switches[edge])
            self.addLink(edge_switches[edge], fabric_switch)

def main():
    num_hosts = args.num_hosts
    num_edges = args.num_edges
    mode = args.mode
    edge_thrift_ports = [int(x) for x in args.edge_thrift_ports.split(',')]

    if len(edge_thrift_ports) != num_edges:
        print("E: Number of edge thrift ports must match edge switches")
        exit()
    if num_edges * num_hosts > 254:
        print("E: Too many edge switches and hosts to support current IP address assignment.")
        exit()

    topo = StarTopo(args.behavioral_exe,
                    args.edge_json,
                    args.fabric_json,
                    edge_thrift_ports,
                    args.fabric_thrift_port,
                    args.pcap_dump,
                    args.enable_debugger,
                    num_hosts,
                    num_edges)

    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4Switch,
                  controller = None)
    net.start()

    total_hosts = num_edges * num_hosts
    for n in range(total_hosts):
        h = net.get('h%d' % (n + 1))
        h.setDefaultRoute("dev eth0")
        h.describe()

    for n in range(num_edges):
        s = net.get('s%d' % (n+1))
        for k in range(num_hosts+1):
            s.disable_ipv6('s%d-eth%d' % (n+1, k+1))
    s = net.get('s%d' % (num_edges + 1))
    for k in range(num_edges):
        s.disable_ipv6('s%d-eth%d' % (num_edges+1, k+1))

    sleep(1)

    print("Ready !")

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
