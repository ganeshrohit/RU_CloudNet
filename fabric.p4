/* Minimal P4 skeleton code adapted from example in
  https://opennetworking.org/news-and-events/blog/getting-started-with-p4/
*/

#include <core.p4>
#include <v1model.p4>

typedef bit<48> EthernetAddress;
typedef bit<32> IPv4Address;

/* HEADER DEFINITIONS */

header ethernet_t {
    EthernetAddress dst_addr;
    EthernetAddress src_addr;
    bit<16>         ether_type;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    IPv4Address src_addr;
    IPv4Address dst_addr;
}

header arp_t {
    bit<16> hardware_type;
    bit<16> protocol_type;
    bit<8>  hardware_addr_len;
    bit<8>  protocol_addr_len;
    bit<16> op_code;
    EthernetAddress sender_hw_addr;
    IPv4Address sender_proto_addr;
    EthernetAddress dest_hw_addr;
    IPv4Address dest_proto_addr;
}

header cust_t {
    bit<7> dest_switch;
    bit<16> ethertype;
    bit<9> tenant;
}

struct headers_t {
    ethernet_t ethernet;
    cust_t     cust;
    ipv4_t     ipv4;
    arp_t      arp;
}

struct metadata_t {
    IPv4Address destination_addr;
}

error {
    IPv4IncorrectVersion,
    IPv4OptionsNotSupported
}

/* PARSER */

parser my_parser(packet_in packet,
                out headers_t hd,
                inout metadata_t meta,
                inout standard_metadata_t standard_meta)
{
    state start {
        packet.extract(hd.ethernet);
        transition select(hd.ethernet.ether_type) {
            0xFFFF:  parse_cust;
            0x0800:  parse_ipv4;
            0x0806:  parse_arp;
            default: accept;
        }
    }

    state parse_cust {
        packet.extract(hd.cust);
        transition select(hd.cust.ethertype) {
            0x0800:  parse_ipv4;
            0x0806:  parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hd.ipv4);
        verify(hd.ipv4.version == 4w4, error.IPv4IncorrectVersion);
        verify(hd.ipv4.ihl == 4w5, error.IPv4OptionsNotSupported);
        meta.destination_addr = hd.ipv4.dst_addr;
        transition accept;
    }

    state parse_arp {
        packet.extract(hd.arp);
        meta.destination_addr = hd.arp.dest_proto_addr;
        transition accept;
    }    
}

/* DEPARSER */

control my_deparser(packet_out packet,
                   in headers_t hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cust);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.arp);
    }
}

/* CHECKSUM CALCULATION AND VERIFICATION */

control my_verify_checksum(inout headers_t hdr,
                         inout metadata_t meta)
{
    apply { }
}

control my_compute_checksum(inout headers_t hdr,
                          inout metadata_t meta)
{
    apply { }
}

/* INGRESS PIPELINE */

control my_ingress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata)
{
    bool dropped = false;

    action drop_action() {
        mark_to_drop(standard_metadata);
        dropped = true;
    }

    action to_port_action(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table ipv4_match {
        key = {
            meta.destination_addr: lpm;
        }
        actions = {
            drop_action;
            to_port_action;
        }
        size = 1024;
        default_action = drop_action;
    }

    table switch_match {
        key = {
            hdr.cust.dest_switch: exact;
        }
        actions = {
            drop_action;
            to_port_action;
        }
        size = 1024;
        default_action = drop_action;
    }

    apply {

        if (hdr.cust.isValid()) {
            switch_match.apply();
        } else {
            ipv4_match.apply();
        }

        /* ipv4_match.apply(); */

        if (dropped) return;
    }
}

/* EGRESS PIPELINE */

control my_egress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata)
{
    apply { }
}

/* SWITCH PACKAGE DEFINITION */

V1Switch(my_parser(),
         my_verify_checksum(),
         my_ingress(),
         my_egress(),
         my_compute_checksum(),
         my_deparser()) main;

