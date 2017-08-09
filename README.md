# GraphTor

This is tool written in Perl for network diagram drawing for Shadows Tor plugin.

## Usage
``graphtor.pl [OPTIONS]``

Mandatory option:
* ``-c/--config=PATH``    path to main configuration file in XML format
  
Optional options:
* ``-p/--pcap=FILE``      	name of the combined output pcap file without extension (default: output)
* ``-o/--output=FILE``    	name of the diagram without extension (default: diagram) - results in .png file
* ``-l/--levels=NUM``     	number of levels of the diagram (default: 4)
* ``-d/--digraph``        	output directed graph (by default is undirected)
* ``-t/--types=[c|s|r]``		which types of nodes to ignore in output (c - client, s - server, r - relay)
* ``-n/--nodes=N1,N2,...``	comma-separated list of nodes (default: all nodes selected; if only one or two specified, diagram contains all neighbouring nodes)
* ``-h/--help/?``				prints this help

### Dependencies
GraphTor is a Perl script, additionally needs two Perl modules installed:
* XML::Twig
* GetOpt::Long

Furthermore, it needs also following tools:
* Wireshark (mergecap, tshark)
* GraphViz (unflatten, dot)

## Compatibility
Script was created on CentOS 7. It works with Perl 5.16.3, Wireshark 1.10.14 and GraphViz 2.30.1.

