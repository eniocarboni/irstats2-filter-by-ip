$c->{'irstats2_filter_ipcidr_blocks'}={
	# use a single ip or ip/cidr or ip/netmask or ip range ip_start-ip_end
	# See EPrints::Plugin::Stats::Filter::IP
	ranges=>[
		#'127.0.0.1',
		#'192.168.0.0/16',
		#'172.16.0.0/255.240.0.0',
		#'10.0.0.0-10.255.255.255',
	],
	# write some debug message on STDERR if debug=1
	debug=>0,
};
