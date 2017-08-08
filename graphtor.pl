#!/usr/bin/perl

use strict;
use warnings;
use XML::Twig;
use Getopt::Long qw(GetOptions);
Getopt::Long::Configure qw(gnu_getopt);

## VARIABLES ##
my $config;
my $pcap = "output";
my $pictureName = "diagram";
my $digraph = undef;
my @interests;
my $interests1;
my $levels = 4;
my @typeIgnore;
my $typeIgnore1;	
my $typeC = undef;
my $typeR = undef;
my $typeS = undef;
my $help = undef;

my $USAGE = <<"USAGE";
Usage: graphtor.pl [OPTIONS]

Mandatory option:
	-c	--config=PATH	path to main configuration file in XML format

Other options:
	-p	--pcap=FILE		name of the combined output pcap file without extension (deafult: output)
	-o	--output=FILE		name of the diagram without extension (defualt: diagram)
	-l	--levels=NUM		number of levels of the diagram (default: 4)
	-d	--digraph		output directed graph
	-t	--types=[c|s|r]		which types of nodes to ignore in output (c - client, s - server, r - relay)
	-n	--nodes=N1,N2,...	comma-separated list of nodes (default: all nodes selected; if only one or two specified, diagram contains all neighbouring nodes)
	-h,? --help			prints this help
USAGE

GetOptions(
	'config|c=s' => \$config,
	'pcap|p=s' => \$pcap,
	'output|o=s' => \$pictureName,
	'levels|l=s' => \$levels,
	'digraph|d' => \$digraph,
	'type|t=s' => \$typeIgnore1,
	'nodes|n=s' => \$interests1,
	'help|h|?' => \$help,
	) or die $USAGE;

if ($help)
{
	die $USAGE;
}

if(!$config)
{
	die "Specify mandatory fields!\n\n".$USAGE;
}

if (length $interests1)
{
	@interests = split(' |,',$interests1);
}

my $arrLen = scalar(@interests);
open(my $fhLog, "> graphtor.log");
print $fhLog "Input parameters:\n   config: $config\n   pcap: $pcap\n   picture: $pictureName\n   nodes: @interests\n   type to ignore: @typeIgnore\n\n";
print $fhLog "Number of interests: $arrLen\n";

my $origInterest1;
my $origInterest2 = undef;
# Checking number of interests given (if 1 or 2: add all neighbours to interests; if 0: all nodes are interests)
my $interestsNumber = 2;
if ($arrLen == 2)
{
	$interestsNumber = 1;
	$origInterest1 = $interests[0];
	$origInterest2 = $interests[1];
}
elsif ($arrLen == 1)
{
	$interestsNumber = 1;
	$origInterest1 = $interests[0];
}
elsif ($arrLen == 0)
{
	$interestsNumber = 0;
}

# part for ignoring types: r - relay, c - client, s - server (keeps only first two)
if (length $typeIgnore1)
{
	@typeIgnore = split(' |,', $typeIgnore1);
	foreach my $t (@typeIgnore)
	{
		chomp($t);
		if ($t =~ /r/)
		{
			$typeR = 1;
		}
		elsif ($t =~ /s/)
		{
			$typeS = 1;
		}
		elsif ($t =~ /c/)
		{
			$typeC = 1;
		}
	}
}

## STEP 1 ##
# Preparing for processing
## step 1.1 ##
# Mapping IPs to clients
# Parameters:
my %mapIpToClient;	# mapping IPs to clients
my @filesToMerge;	# which files we will merge into one

# Getting absolute path of shadow config (for pcap files)
my @pathParts = split('/', $config);
my $absolutePath = join('/', @pathParts[0..$#pathParts - 1]) . "/";
print $fhLog "Absolute path: $absolutePath\n";

## step 1.2 ##
# Parsing XML configuration file #
# Parameters:
my %allNodes;		# data for all nodes: key = nodeID, values: pcapdir, typehint, iphint, starttime
my $twig = new XML::Twig(TwigHandlers=> { node => \&Node });
$twig->parsefile($config);


## step 1.3 ##
# Preparing string for merging all .pcap files
my $filesToMergeString = "";
print $fhLog "Files to merge:\n";

foreach my $file (@filesToMerge)
{
	chomp($file);
	print $fhLog "   " . $file . "\n";
	$filesToMergeString  .= $file . " "; 
}

## STEP 2 ##
# Merge all files
chmod 0766, $filesToMergeString;
print $fhLog "Files to merge: $filesToMergeString\n";
print $fhLog "Merging files into output/$pcap.pcap... ";
my $mergeCommand = "mergecap -w output/$pcap.pcap $filesToMergeString";
system(`$mergeCommand`);
chmod 0644, $filesToMergeString;
print "Finished merging.\n";
print $fhLog "Finished merging.\n";

## STEP 3 ##
# Get all unique pairs of IPs that communicate to each other
my $ipPairsUniqueCsv = "output/IPpairs_unique.csv";
print $fhLog "All unique IPs are in $ipPairsUniqueCsv.\n";
my $tsharkCommandUniq = "tshark -r output/$pcap.pcap -T fields -e ip.src -e ip.dst -E separator=, | cut -d , -f1,2 | sort | uniq > $ipPairsUniqueCsv";
system(`$tsharkCommandUniq`);

# if $interestsNumber = 1: add neighbours to interests
if ($interestsNumber == 1)
{
	
	open(my $fhIps, '<', $ipPairsUniqueCsv) or die "Could not open file $ipPairsUniqueCsv!\n";
	while (my $ip = <$fhIps>)
	{
		my @pair = split(',', $ip);
		my $ip0 = $mapIpToClient{$pair[0]};
		chomp($pair[1]);
		my $ip1 = $mapIpToClient{$pair[1]};
		# check if type should be ignored
		# !$type(C|S|R); cekiraj ce je interest osnovni -ta se ne ignorira!
		if (defined($ip0) && ($ip0 ne $origInterest1) && ( (!defined($origInterest2)) || (defined($origInterest2) && $ip0 ne $origInterest2) ) && ($typeC || $typeR || $typeS))
		{
			my $currType0 = $allNodes{$ip0}{'type'};
			if ( ( ($currType0 eq 'client') && !$typeC) || ( ($currType0 eq 'relay') && !$typeR ) || ( ($currType0 eq 'server') && !$typeS ) && (! grep(/^$ip0$/, @interests)))
			{
				push @interests, $ip0;
			}
		}
		else {
			if (defined($ip0) && (! grep(/^$ip0$/, @interests)))
			{
				push @interests, $ip0;
			}
		}
		
		if (defined($ip1) && ($ip1 ne $origInterest1) && ( (!defined($origInterest2)) || (defined($origInterest2) && $ip1 ne $origInterest2) ) && ($typeC || $typeR || $typeS))
		{
			my $currType1 = $allNodes{$ip1}{'type'};
			if ( ( ($currType1 eq 'client') && !$typeC) || ( ($currType1 eq 'relay') && !$typeR ) || ( ($currType1 eq 'server') && !$typeS ) && (! grep(/^$ip1$/, @interests)))
			{
				push @interests, $ip1;
			}
		}
		else
		{
			if (defined($ip1) && (! grep(/^$ip1$/, @interests)))
			{
				push @interests, $ip1;
			}
		}
	}
	close $fhIps;
	@interests = grep defined, @interests;
}

## STEP 4 ##
# Creating network diagram picture
my $pictureNameDot = "output/$pictureName.dot";
print $fhLog "Picture configuration: $pictureNameDot\nConstructing... ";
system(`touch $pictureNameDot`);
ConstructDot();
print $fhLog "Constructed!\n";
print $fhLog "Preprocess dot... ";
#chmod 0644, $pictureNameDot;
my $pictureNameDot2 = "output/$pictureName-2.dot";
my $unflattenCmd = "unflatten -f -l $levels -o $pictureNameDot2 $pictureNameDot";
system(`$unflattenCmd`);
print $fhLog "finished!\nCreating diagram... ";
my $dotCommand = "dot -Tpng $pictureNameDot2 -o output/$pictureName.png";
system(`$dotCommand`);
print $fhLog "finished!\n";
close $fhLog;

## Helper subroutines ##

# Parsing .csv to .dot for graphical representation of network
sub ConstructDot
{
 	open(my $fhDot, '>', $pictureNameDot) or die "Could not open file $pictureNameDot!\n";
    open(my $fhCsv, '<', $ipPairsUniqueCsv) or die "Could not open file $ipPairsUniqueCsv!\n";

	if ($digraph)
    {    
        print $fhDot "digraph networkDiagram {\n";
    }
    else
    {
        print $fhDot "graph networkDiagram {\n";
    }
    
     my %dotMappings;
     my $nodeId = 0;

	foreach my $interest (@interests)
	{
		$dotMappings{$interest}{'type'} = $allNodes{$interest}{'type'};
	    $dotMappings{$interest}{'node'} = "node$nodeId";
    	print $fhDot "$dotMappings{$interest}{'node'} [label=<<table border=\"0\"><tr><td height=\"20\"><img src=\"icons/$dotMappings{$interest}{'type'}_icon.png\" scale=\"true\" /></td><td>$interest</td></tr></table>> shape=box fontname=\"arial bold\"];\n";
    	$nodeId++;
    }
    
    my @ipPairsDone;
    while (my $line = <$fhCsv>)
    {
        my @ips = split(',', $line);
        #my $ipSrc = $ips[0];
        #my $ipDst = $ips[1];
        chomp($ips[1]);
        if (exists $mapIpToClient{$ips[0]} and exists $mapIpToClient{$ips[1]} and exists $dotMappings{$mapIpToClient{$ips[0]}} and exists $dotMappings{$mapIpToClient{$ips[1]}} )
        {
            my $tmp;
            if ($digraph)
            {            
                $tmp = "\t$dotMappings{$mapIpToClient{$ips[0]}}{'node'} -> $dotMappings{$mapIpToClient{$ips[1]}}{'node'};\n";
                print $fhDot $tmp;
            }
            else
            {
                if ( ! defined Contains($ips[0], $ips[1], @ipPairsDone) )
                {
                    push @ipPairsDone, "$ips[0] $ips[1]";
                    $tmp = "\t$dotMappings{$mapIpToClient{$ips[0]}}{'node'} -- $dotMappings{$mapIpToClient{$ips[1]}}{'node'};\n";
                    print $fhDot $tmp;
                }
            }
        }
    }
    print $fhDot "}\n";
    close $fhCsv;
    close $fhDot;
   
}

# Checking if ipSrc and ipDst are already written for graph
sub Contains()
{
    my ($src, $dst, @done) = @_;
    if (grep (/($src $dst|$dst $src)/, @done))
    {
    	return 1;
    }
    
    return undef;
}

# Parsing XML
sub Node
{
    my ($twig, $node) = @_;
    my %nodes;
    if ($node->att('quantity') > 1)
    {
    	for (my $i = 1; $i <= $node->att('quantity'); $i++)
    	{
    		$nodes{id} = $node->att('id') . $i;
    		my $name = $node->att('id') . $i;
    		$allNodes{$nodes{id}}{pcapdir} = $node->att('pcapdir');
			$allNodes{$nodes{id}}{type} = $node->att('typehint');
			if ($allNodes{$nodes{id}}{type} =~ /client/)
			{
				$allNodes{$nodes{id}}{ip} = "N/A";
			}
			else
			{
				$allNodes{$nodes{id}}{ip} = $node->att('iphint');
			}
			
			my $dir = $absolutePath . $allNodes{$nodes{id}}{pcapdir};
			my $file = `ls $dir | grep -E "$name-([0-9]{1,3}\.){3}[0-9]{1,3}.pcap" | grep -v "127.0.0.1"`;
			if (grep(/$name/, @interests))
			{
				push @filesToMerge, $dir.$file;
			}
			if ($interestsNumber == 0)
			{
				push @interests, $name;
				push @filesToMerge, $dir.$file;
			}
			$file =~ s/.*-(([0-9]{1,3}\.){3}[0-9]{1,3}).pcap/$1/;
			chomp($file);
			$mapIpToClient{$file} = $name;
    	}
    }
    else
    {
		$nodes{id} = $node->att('id');
		my $name = $node->att('id');
		$allNodes{$nodes{id}}{pcapdir} = $node->att('pcapdir');
		$allNodes{$nodes{id}}{type} = $node->att('typehint');
		if ($allNodes{$nodes{id}}{type} =~ /client/)
		{
		    $allNodes{$nodes{id}}{ip} = "N/A";
		}
		else
		{
		    $allNodes{$nodes{id}}{ip} = $node->att('iphint');
		}
		
		my $dir = $absolutePath . $allNodes{$nodes{id}}{pcapdir};
		my $file = `ls $dir | grep -E "$name-([0-9]{1,3}\.){3}[0-9]{1,3}.pcap" | grep -v "127.0.0.1"`;

		if (grep(/$name/, @interests))
		{
			push @filesToMerge, $dir.$file;
		}
		if ($interestsNumber == 0)
		{
			push @interests, $name;
			push @filesToMerge, $dir.$file;
		}
		$file =~ s/.*-(([0-9]{1,3}\.){3}[0-9]{1,3}).pcap/$1/;
		chomp($file);
		$mapIpToClient{$file} = $name;
    }
}
