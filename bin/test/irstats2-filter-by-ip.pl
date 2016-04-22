#!/usr/bin/perl -w 
# The script should be installed in $EPRINTS_PATH/archives/<id>/bin/test

=head1 NAME

B<irstats2-filter-by-ip.pl> - test script for Filter module for Irstats2 to filter accesslog by ip/cidr or ip ranges or ip/netmask

=head1 DESCRIPTION

This script is a simple script to test irstats2-filter-by-ip pachage.

=head1 SINOPSIS

B<./irstats2-filter-by-ip.pl> <archiveid> <ip_to_test>

=cut

use FindBin;
use lib "$FindBin::Bin/../../../../perl_lib";

use EPrints;
use Getopt::Long;
use Pod::Usage;

use strict;

our ($noise);
my $version = 0;
my $verbose = 0;
my $quiet = 0;
my $help = 0;
my $man = 0;

# Inizio Main
Getopt::Long::Configure("permute");

GetOptions( 
	'help|?' => \$help,
	'man' => \$man,
	'version' => \$version,
	'verbose+' => \$verbose,
	'quiet' => \$quiet,
) || pod2usage( 1 );
pod2usage( 1 ) if $help;

$noise = 1;
$noise = 0 if( $quiet );
$noise = 1+$verbose if( $verbose );

# Set STDOUT to auto flush (without needing a \n)
$|=1;

my $repoid = shift @ARGV;
#my $datasetid =shift || 'access';
my $datasetid='access';
pod2usage(1) unless defined $repoid;

my $session = new EPrints::Session( 1 , $repoid , $noise );
if( !defined $session )
{
	print STDERR "Failed to load repository: $repoid\n";
	exit 1;
}

$noise=$verbose;

my $ipfilter=$session->plugin("Stats::Filter::IP");

print "checking ip $ARGV[0]: ".$ipfilter->filter_record({requester_id=>$ARGV[0]})."\n";

$session->terminate();

