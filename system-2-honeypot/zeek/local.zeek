# Zeek local site policy — Group 3 (Network Traffic Monitoring, DNS/HTTP/
# TLS metadata monitoring, Connection Monitoring, Protocol Monitoring).
#
# Zeek ships its own extensive base scripts; this file only adds the
# HoneyShield-specific bits: JSON logging (so Filebeat can ship structured
# events straight to OpenSearch) and a couple of local notice policies
# tuned for a honeypot network where "normal" traffic barely exists.

@load base/frameworks/notice
@load base/frameworks/logging
@load policy/tuning/json-logs.zeek

# All logs as newline-delimited JSON — matches how Filebeat is configured
# to read them (see ../filebeat/filebeat.yml).
redef LogAscii::use_json = T;

# Every inbound connection on a honeypot network is inherently interesting
# — lower the threshold for what counts as "worth a notice" compared to
# Zeek's production-network defaults.
redef Notice::type_suppress_by = 0sec;

event zeek_init()
	{
	print "HoneyShield X Zeek sensor started — logging as JSON to logs/current/*.log";
	}

# Flag any connection where the honeypot host itself initiates traffic
# outbound — on a honeypot, "the trap is calling out" is a strong signal
# of a real compromise/callback rather than an attacker probing in.
event connection_established(c: connection)
	{
	if ( Site::is_local_addr(c$id$orig_h) && ! Site::is_local_addr(c$id$resp_h) )
		{
		NOTICE([$note=Notice::Type("HoneyShield::UnexpectedOutbound"),
		        $msg=fmt("Honeypot host %s initiated outbound connection to %s:%s — verify this was expected test traffic",
		                 c$id$orig_h, c$id$resp_h, c$id$resp_p),
		        $conn=c,
		        $identifier=cat(c$id$orig_h, c$id$resp_h)]);
		}
	}


