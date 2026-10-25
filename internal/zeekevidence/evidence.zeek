# Zeek side of `quarant zeek evidence`. Zeek parses HTTP, TLS, MQTT, FTP,
# SSH and SNMP (found by content, so the port does not matter) and this
# script writes one row per TLS session, HTTP request, MQTT CONNECT, FTP
# login, SSH session and SNMP exchange to quarant_evidence.log, plus one row
# per software name and version a home-network host names (Zeek's software
# framework: HTTP Server and User-Agent, SSH and FTP banners, DHCP vendor
# class). Quarant turns the rows into evidence for the ETSI
# provisions (internal/zeekevidence).
#
# Only names and shapes are logged, never values: header names, URL
# parameter names, body key names, the Authorization scheme, and whether a
# username or password was present, and whether an SNMP community equals a
# well-known default (compared in memory). Every other Zeek log is disabled, so
# URLs, cookies and FTP arguments are not written to disk at all.
#
# Derived from scripts/accuracy/gt.zeek (the ground truth of E11-E14); that
# script is kept unchanged so the earlier measurements stay reproducible.
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/mqtt
@load base/protocols/ftp
@load base/protocols/ssh
@load base/protocols/snmp
@load base/files/x509
@load base/frameworks/software
@load policy/protocols/http/software
@load policy/protocols/ssh/software
@load policy/protocols/ftp/software
@load policy/protocols/dhcp/software

# Track every host; only private addresses are written (see log_software).
redef Software::asset_tracking = ALL_HOSTS;

module QuarantEvidence;

export {
	redef enum Log::ID += { LOG };
	type Info: record {
		ts: time &log;
		uid: string &log;
		kind: string &log;
		orig_mac: string &log &optional;
		resp_mac: string &log &optional;
		orig_h: addr &log;
		orig_p: port &log;
		resp_h: addr &log;
		resp_p: port &log;
		# TLS
		version: string &log &optional;
		cipher: string &log &optional;
		client_versions: string &log &optional;
		sni: string &log &optional;
		# HTTP
		method: string &log &optional;
		host: string &log &optional;
		status: count &log &optional;
		req_headers: set[string] &log &optional;
		auth_scheme: string &log &optional;
		uri_params: set[string] &log &optional;
		req_body_keys: set[string] &log &optional;
		resp_body_keys: set[string] &log &optional;
		orig_mime: vector of string &log &optional;
		req_body_len: count &log &optional;
		# TLS: the server's leaf certificate (not sent in clear in TLS 1.3)
		cert_key_type: string &log &optional;
		cert_key_length: count &log &optional;
		cert_sig_alg: string &log &optional;
		cert_self_signed: bool &log &optional;
		cert_expired: bool &log &optional;
		# the issuer's distinguished name: public, and the only way to tell
		# an interception proxy's certificate from the server's own
		cert_issuer: string &log &optional;
		established: bool &log &optional;
		# MQTT / FTP
		has_username: bool &log &optional;
		has_password: bool &log &optional;
		anonymous: bool &log &optional;
		# SSH: the negotiated algorithms and the software banners
		ssh_version: count &log &optional;
		ssh_kex: string &log &optional;
		ssh_cipher: string &log &optional;
		ssh_mac: string &log &optional;
		ssh_host_key: string &log &optional;
		ssh_client: string &log &optional;
		ssh_server: string &log &optional;
		# SNMP v1/v2c: the community itself is never logged
		snmp_version: string &log &optional;
		snmp_has_community: bool &log &optional;
		snmp_default_community: bool &log &optional;
		# The address that answered (the agent), when a response was seen
		snmp_agent: addr &log &optional;
		snmp_responses: count &log &optional;
		# Software: the name and the numeric version only. The unparsed
		# string and Zeek's "addl" part are not written: a User-Agent can
		# carry identifiers there.
		sw_host: addr &log &optional;
		sw_type: string &log &optional;
		sw_name: string &log &optional;
		sw_version: string &log &optional;
		# The banner names a distribution (Ubuntu, Debian, ...), whose
		# packages take fixes without changing the upstream version.
		sw_distro: bool &log &optional;
	};
}

# Names that suggest a secret; only names that match are kept for bodies.
# The word must sit at the start or end of the name or next to a separator,
# so that random strings ("...xpwdrr...") are not taken for names. Same
# rule as secretName in zeekevidence.go.
const secret_name = /(^|[_.\[-])(pass|pwd|token|secret|api[_-]?key|apikey|auth|session|sid|sign)|(pass|passwd|password|pwd|token|secret|apikey|accesskey|secretkey|privatekey|auth|session|sid|sign|signature)($|[_.\]-])/i;
const key_pat = /[\"']?[A-Za-z0-9_\-\.]{1,40}[\"']?[ \t]*[:=]/;
const param_name = /^[A-Za-z0-9_\-\.\[\]]{1,40}$/;

# SNMP communities that ship as defaults on most agents (RFC 1157 examples,
# vendor defaults). Compared in memory; the community is not logged.
const default_communities = set("public", "private");

redef record HTTP::Info += {
	qe_req_headers: set[string] &default=set();
	qe_auth: string &optional;
	qe_params: set[string] &default=set();
	qe_req_keys: set[string] &default=set();
	qe_resp_keys: set[string] &default=set();
	qe_req_seen: count &default=0;
	qe_resp_seen: count &default=0;
	qe_orig_mac: string &optional;
	qe_resp_mac: string &optional;
};

redef record SSH::Info += {
	qe_orig_mac: string &optional;
	qe_resp_mac: string &optional;
};

redef record SNMP::Info += {
	qe_orig_mac: string &optional;
	qe_resp_mac: string &optional;
	qe_agent: addr &optional;
};

redef record SSL::Info += {
	qe_client_versions: string &optional;
	qe_orig_mac: string &optional;
	qe_resp_mac: string &optional;
};

redef record connection += {
	qe_ftp_logged: bool &default=F;
	qe_ftp_user: bool &default=F;
	qe_ftp_anon: bool &default=F;
};

event zeek_init() &priority=-10
	{
	# Only the default filters are removed: a disabled stream also stops its
	# log event (HTTP::log_http, SSL::log_ssl), which this script needs.
	for ( id in Log::active_streams )
		Log::remove_default_filter(id);
	Log::create_stream(QuarantEvidence::LOG, [$columns=Info, $path="quarant_evidence"]);
	}

function base(c: connection, kind: string): Info
	{
	local r = Info($ts=network_time(), $uid=c$uid, $kind=kind,
	               $orig_h=c$id$orig_h, $orig_p=c$id$orig_p,
	               $resp_h=c$id$resp_h, $resp_p=c$id$resp_p);
	if ( c$orig?$l2_addr ) r$orig_mac = c$orig$l2_addr;
	if ( c$resp?$l2_addr ) r$resp_mac = c$resp$l2_addr;
	return r;
	}

# The log events can fire after the connection is gone, so the MACs are
# copied into the protocol records early.
function from_rec(id: conn_id, uid: string, ts: time, kind: string, om: string, rm: string): Info
	{
	local r = Info($ts=ts, $uid=uid, $kind=kind, $orig_h=id$orig_h, $orig_p=id$orig_p,
	               $resp_h=id$resp_h, $resp_p=id$resp_p);
	if ( om != "" ) r$orig_mac = om;
	if ( rm != "" ) r$resp_mac = rm;
	return r;
	}

function body_keys(data: string, out: set[string])
	{
	for ( m in find_all(data, key_pat) )
		{
		local k = gsub(m, /[\"' \t:=]/, "");
		k = to_lower(k);
		if ( secret_name in k )
			add out[k];
		}
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=3
	{
	if ( ! c?$http ) return;
	if ( c$orig?$l2_addr ) c$http$qe_orig_mac = c$orig$l2_addr;
	if ( c$resp?$l2_addr ) c$http$qe_resp_mac = c$resp$l2_addr;
	# The unescaped URI, so that an encoded query (%26, %3d) is split into
	# its keys too and no value ends up in a key name.
	local q = find_last(unescaped_URI, /\?.*/);
	if ( q == "" ) return;
	for ( _, kv in split_string(sub(q, /^\?/, ""), /&/) )
		{
		# A part without "=" may be a bare value, so it is not kept.
		if ( /=/ !in kv ) next;
		local k = split_string1(kv, /=/)[0];
		if ( param_name in k )
			add c$http$qe_params[to_lower(k)];
		}
	}

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string) &priority=3
	{
	if ( ! c?$http || ! is_orig ) return;
	add c$http$qe_req_headers[to_lower(name)];
	if ( name == "AUTHORIZATION" )
		{
		local scheme = split_string1(value, / /)[0];
		# A header without a scheme is a bare value.
		if ( /[ ]/ in value && param_name in scheme )
			c$http$qe_auth = to_lower(scheme);
		else
			c$http$qe_auth = "none";
		}
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=3
	{
	if ( ! c?$http ) return;
	if ( is_orig && c$http$qe_req_seen < 8192 )
		{
		c$http$qe_req_seen += length;
		body_keys(data, c$http$qe_req_keys);
		}
	else if ( ! is_orig && c$http$qe_resp_seen < 8192 )
		{
		c$http$qe_resp_seen += length;
		body_keys(data, c$http$qe_resp_keys);
		}
	}

event HTTP::log_http(rec: HTTP::Info)
	{
	local r = from_rec(rec$id, rec$uid, rec$ts, "http", rec?$qe_orig_mac ? rec$qe_orig_mac : "", rec?$qe_resp_mac ? rec$qe_resp_mac : "");
	if ( rec?$method ) r$method = rec$method;
	if ( rec?$host ) r$host = rec$host;
	if ( rec?$status_code ) r$status = rec$status_code;
	r$req_headers = rec$qe_req_headers;
	if ( rec?$qe_auth ) r$auth_scheme = rec$qe_auth;
	r$uri_params = rec$qe_params;
	r$req_body_keys = rec$qe_req_keys;
	r$resp_body_keys = rec$qe_resp_keys;
	if ( rec?$orig_mime_types ) r$orig_mime = rec$orig_mime_types;
	r$req_body_len = rec$request_body_len;
	Log::write(QuarantEvidence::LOG, r);
	}

function set_macs(c: connection)
	{
	if ( c$orig?$l2_addr ) c$ssl$qe_orig_mac = c$orig$l2_addr;
	if ( c$resp?$l2_addr ) c$ssl$qe_resp_mac = c$resp$l2_addr;
	}

event ssl_extension_supported_versions(c: connection, is_client: bool, versions: index_vec)
	{
	if ( ! is_client || ! c?$ssl ) return;
	local names: vector of string = vector();
	for ( _, v in versions )
		names += SSL::version_strings[v];
	c$ssl$qe_client_versions = join_string_vec(names, ",");
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=3
	{
	if ( ! c?$ssl ) return;
	if ( ! c$ssl?$qe_client_versions )
		c$ssl$qe_client_versions = "max=" + SSL::version_strings[version];
	set_macs(c);
	}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=3
	{
	if ( c?$ssl ) set_macs(c);
	}

event SSL::log_ssl(rec: SSL::Info)
	{
	local r = from_rec(rec$id, rec$uid, rec$ts, "tls", rec?$qe_orig_mac ? rec$qe_orig_mac : "", rec?$qe_resp_mac ? rec$qe_resp_mac : "");
	if ( rec?$version ) r$version = rec$version;
	if ( rec?$cipher ) r$cipher = rec$cipher;
	if ( rec?$qe_client_versions ) r$client_versions = rec$qe_client_versions;
	if ( rec?$server_name ) r$sni = rec$server_name;
	r$established = rec$established;
	if ( rec?$cert_chain && |rec$cert_chain| > 0 && rec$cert_chain[0]?$x509 )
		{
		local cert = rec$cert_chain[0]$x509$certificate;
		if ( cert?$key_type ) r$cert_key_type = cert$key_type;
		if ( cert?$key_length ) r$cert_key_length = cert$key_length;
		r$cert_sig_alg = cert$sig_alg;
		r$cert_self_signed = cert$subject == cert$issuer;
		r$cert_issuer = cert$issuer;
		r$cert_expired = cert$not_valid_after < rec$ts || cert$not_valid_before > rec$ts;
		}
	Log::write(QuarantEvidence::LOG, r);
	}

event ssh_server_version(c: connection, version: string) &priority=-5
	{
	if ( ! c?$ssh ) return;
	if ( c$orig?$l2_addr ) c$ssh$qe_orig_mac = c$orig$l2_addr;
	if ( c$resp?$l2_addr ) c$ssh$qe_resp_mac = c$resp$l2_addr;
	}

event SSH::log_ssh(rec: SSH::Info)
	{
	local r = from_rec(rec$id, rec$uid, rec$ts, "ssh", rec?$qe_orig_mac ? rec$qe_orig_mac : "", rec?$qe_resp_mac ? rec$qe_resp_mac : "");
	if ( rec?$version ) r$ssh_version = rec$version;
	if ( rec?$kex_alg ) r$ssh_kex = rec$kex_alg;
	if ( rec?$cipher_alg ) r$ssh_cipher = rec$cipher_alg;
	if ( rec?$mac_alg ) r$ssh_mac = rec$mac_alg;
	if ( rec?$host_key_alg ) r$ssh_host_key = rec$host_key_alg;
	if ( rec?$client ) r$ssh_client = rec$client;
	if ( rec?$server ) r$ssh_server = rec$server;
	Log::write(QuarantEvidence::LOG, r);
	}

# A GetResponse comes from the agent; to a broadcast request it arrives on a
# connection of its own, where the agent is the originator.
event snmp_response(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU) &priority=-5
	{
	if ( ! c?$snmp ) return;
	c$snmp$qe_agent = is_orig ? c$id$orig_h : c$id$resp_h;
	}

event connection_state_remove(c: connection) &priority=10
	{
	if ( ! c?$snmp ) return;
	if ( c$orig?$l2_addr ) c$snmp$qe_orig_mac = c$orig$l2_addr;
	if ( c$resp?$l2_addr ) c$snmp$qe_resp_mac = c$resp$l2_addr;
	}

event SNMP::log_snmp(rec: SNMP::Info)
	{
	local r = from_rec(rec$id, rec$uid, rec$ts, "snmp", rec?$qe_orig_mac ? rec$qe_orig_mac : "", rec?$qe_resp_mac ? rec$qe_resp_mac : "");
	r$snmp_version = rec$version;
	r$snmp_has_community = rec?$community && rec$community != "";
	r$snmp_default_community = rec?$community && to_lower(rec$community) in default_communities;
	if ( rec?$qe_agent ) r$snmp_agent = rec$qe_agent;
	r$snmp_responses = rec$get_responses;
	Log::write(QuarantEvidence::LOG, r);
	}

event mqtt_connect(c: connection, msg: MQTT::ConnectMsg)
	{
	local r = base(c, "mqtt");
	r$has_username = msg?$username;
	r$has_password = msg?$password && |msg$password| > 0;
	Log::write(QuarantEvidence::LOG, r);
	}

# One row per FTP connection, at the first PASS with a non-empty argument.
event ftp_request(c: connection, command: string, arg: string)
	{
	if ( command == "USER" )
		{
		c$qe_ftp_user = T;
		c$qe_ftp_anon = to_lower(arg) == "anonymous" || to_lower(arg) == "ftp";
		}
	if ( command == "PASS" && arg != "" && ! c$qe_ftp_logged )
		{
		c$qe_ftp_logged = T;
		local r = base(c, "ftp");
		r$has_username = c$qe_ftp_user;
		r$has_password = T;
		r$anonymous = c$qe_ftp_anon;
		Log::write(QuarantEvidence::LOG, r);
		}
	}

event Software::log_software(rec: Software::Info)
	{
	if ( ! Site::is_private_addr(rec$host) )
		return;
	local v = rec$version;
	local ver = "";
	if ( v?$major )
		{
		ver = cat(v$major);
		if ( v?$minor ) ver += cat(".", v$minor);
		if ( v?$minor2 ) ver += cat(".", v$minor2);
		if ( v?$minor3 ) ver += cat(".", v$minor3);
		}
	local r = Info($ts=rec$ts, $uid="", $kind="software", $orig_h=rec$host,
	               $orig_p=rec?$host_p ? rec$host_p : 0/unknown, $resp_h=0.0.0.0, $resp_p=0/unknown);
	r$sw_host = rec$host;
	r$sw_type = cat(rec$software_type);
	r$sw_name = rec$name;
	if ( ver != "" ) r$sw_version = ver;
	if ( rec?$unparsed_version && /[uU]buntu|[dD]ebian|[rR]aspbian|[fF]edora|[rR]ed ?[hH]at|[cC]ent[oO][sS]|deb[0-9]/ in rec$unparsed_version )
		r$sw_distro = T;
	Log::write(QuarantEvidence::LOG, r);
	}
