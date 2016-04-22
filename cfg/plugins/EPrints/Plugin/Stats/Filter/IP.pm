package EPrints::Plugin::Stats::Filter::IP;

use EPrints::Plugin::Stats::Processor;

our @ISA = qw/ EPrints::Plugin::Stats::Processor /;

use strict;

sub new
{
        my( $class, %params ) = @_;
        my $self = $class->SUPER::new( %params );

        $self->{disable} = 0;
	$self->{'conf'}=$self->repository->get_conf('irstats2_filter_ipcidr_blocks') || {};
	$self->{'debug'}= exists $self->{'conf'}->{'debug'} ? $self->{'conf'}->{'debug'} : 0;
        return $self;
}
        
sub filter_record {
        my ($self, $record) = @_;
	my ($ip,$found,$iprange,$ip_start,$ip_end);
        $ip = $record->{requester_id};
        return 0 unless( defined $ip );
	$found=0;
	unless (exists $self->{'ranges'}) {
		$self->ipcidrblocksToRanges();
		print STDERR "[Stats::Filter::IP::filter_record] range ip calcolati: ".join (",",@{$self->{'ranges'}})."\n" if $self->{'debug'};
	}
	foreach $iprange (@{$self->{'ranges'}} ) {
		($ip_start,$ip_end)=split(/-/,$iprange);
		next if $self->_ipcmp($ip,$ip_start) < 0;
		next if $self->_ipcmp($ip_end, $ip)  < 0;
		$found=1; last;
	}
	print STDERR "[Stats::Filter::IP::filter_record] found ip $ip in accessid=$record->{accessid}\n" if $found && $self->{'debug'};
	return $found;
}

# CIDR methods

# Parameter: ip1, ip2 (ip1 and ip2 like 10.0.1.2)
# Return -1 if ip1 < ip2
# return  0 if ip1 = ip2
# return  1 if ip1 > ip2
sub _ipcmp {
    my $self=shift;
    my $ip1=shift;
    my $ip2=shift;
    my (@ip1_el,@ip2_el);
    @ip1_el=split (/\./, $ip1);
    @ip2_el=split (/\./, $ip2);
    print STDERR "[Stats::Filter::IP::_ipcmp] Different number of octets in IP addresses\n" if  ($#ip1_el != $#ip2_el) && $self->{'debug'};
    while ($#ip1_el >= 0 && $ip1_el[0] == $ip2_el[0]) {
	shift @ip1_el;
	shift @ip2_el;
    }
    return 0 if $#ip1_el < 0;
    return $ip1_el[0] <=> $ip2_el[0];
}

sub _ipcidrblocksToRanges {
    my $self=shift;
    my @ips=@_;
    my ($cidr,@ips2,$octet,$n,$start,$end);
    $cidr=shift @ips;
    if ($cidr == 0) {
	grep { $_=0 } @ips;
	@ips2=@ips;
	grep { $_=255 } @ips2;
	return ( join(".", @ips), join(".", @ips2));
    }
    if ($cidr >= 8) {
	$octet=shift @ips;
	@ips=$self->_ipcidrblocksToRanges($cidr - 8, @ips);
	grep { $_="$octet.$_"; } @ips;
	return @ips;
    }
    $octet=shift @ips;
    grep { $_=0 } @ips;
    @ips2=@ips;
    grep { $_=255 } @ips2;
    ## << = shift bits left. this is equal to 2**(8-$cidr) but more fast
    $n= 1 << (8-$cidr);
    $octet &= ($n-1) ^ 255;
    $start=join (".",$octet,@ips);
    $end=join (".",$octet + ($n-1), @ips2);
    return ($start, $end);
}

sub ipcidrblocksToRanges {
    my $self=shift;
    my ($conf,@r,$cidrs,$ip, $pfix,@ips,$i,@rr,$a,$b,$cidr_or_netmask,$cidr,$prev_octet);
    return if exists $self->{'ranges'} && ref($self->{'ranges'}) eq 'ARRAY';
    $conf=$self->{'conf'};
    if ($conf && ref($conf) eq 'HASH' && exists $conf->{'ranges'} && ref($conf->{'ranges'}) eq 'ARRAY') {
	$cidrs=[ @{$conf->{'ranges'}} ]; # so make a copy 
    }
    else { 
	$self->{'ranges'}=[]; 
	return;
    }
    while (scalar(@$cidrs) > 0) {
	$cidr=shift @$cidrs;
	$cidr =~ s/\s//g;
	$cidr="$cidr-$cidr" unless $cidr =~ /[-\/]/;
	unless ($cidr =~ /(.*)\/(.*)/) {
	    push @r, $cidr;
	    next;
	}
	($ip, $cidr_or_netmask)=($1, $2);
	if ($cidr_or_netmask =~/\./) { # netmask so convert it in cidr
		$cidr=0;
		$prev_octet = 255;
		foreach my $octet (split/\./, $cidr_or_netmask) {
			if($prev_octet != 255 && $octet != 0) {
				print STDERR "[Stats::Filter::IP::ipcidrblocksToRanges] Invalid number $octet (must be 0) in netmask $cidr_or_netmask in $cidr\n" if $self->{'debug'};
				$cidr=-1; last;
			}
			$prev_octet = $octet;
			while ($octet > 0) {
				# check first right bit that must be 1 in netmask
				if (($octet & 128) == 0) { # 128 = 1000 0000
					print STDERR "[Stats::Filter::IP::ipcidrblocksToRanges] Invalid number $prev_octet in netmask [$cidr_or_netmask]\n" if $self->{'debug'};
					$cidr=-1; last;
				}
				$octet=($octet << 1) & 255; # shift bit right than AND with 255 to take only 8 bit
				$cidr++;
			}
			last if $cidr < 0;
		}
		next if $cidr < 0;
	}
	else { $cidr=$cidr_or_netmask; }
	@ips= split (/\.+/, $ip);
	for( $i = $#ips + 1 ; $i < 4 ; $i++ ) { $ips[$i] = 0; }
	grep {
		print STDERR "[Stats::Filter::IP::ipcidrblocksToRanges] $_, in $ip, is not valid [use value in range 0-255]\n" if ($_ < 0 || $_ > 255 || $_ !~ /^[0-9]+$/) && $self->{'debug'};
	} @ips;
	if ($cidr < 0 || $cidr > (($#ips+1) * 8) || $cidr !~ /^[0-9]+$/ ) {
		print STDERR "$cidr, as in '$cidrs', does not make sense\n" if $self->{'debug'};
		next;
	}
	@rr=$self->_ipcidrblocksToRanges($cidr, @ips);
	while ($#rr >= 0) {
	    $a=shift @rr;
	    $b=shift @rr;
	    $a =~ s/\.$//;
	    $b =~ s/\.$//;
	    push @r, "$a-$b";
	}
    }
    $self->{'ranges'}=[@r];
}

1;
