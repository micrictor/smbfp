##! Extended SMB2/3 client fingerprint.
##!
##! Seven features from the unencrypted session establishment are joined with
##! ";" and hashed with MD5:
##!
##!   Dialects;Capabilities;NegContextTypes;Ciphers;Compression;Signing;NtlmsspFlags
##!
##! The first six come from the first SMB2 NEGOTIATE request of a connection,
##! the last from the first NTLMSSP NEGOTIATE (type 1) message sent in a
##! SESSION_SETUP request. Absent features enter as empty strings.
##! The format follows fingerprinting/smb_session_fingerprint.py from
##! https://github.com/fkie-cad/encrypted-smb-forensics.
##!
##! Zeek's SMB analyzer does not expose capabilities, the request's negotiate
##! contexts or the raw NTLMSSP flags, so the client stream is parsed here
##! directly from tcp_contents until both messages have been seen.

@load base/protocols/smb
@load base/frameworks/intel
@load ./smbfp-intel.zeek
@load ./smbfp-clients.zeek

module smbfp;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {
		## Time of the NEGOTIATE request.
		ts:                time    &log;
		uid:               string  &log;
		id:                conn_id &log;
		## MD5 of fingerprint_str.
		fingerprint:       string  &log;
		## The seven features joined with ";".
		fingerprint_str:   string  &log;
		## Dialects offered, in wire order.
		dialects:          string  &log;
		## Capabilities field of the NEGOTIATE request.
		capabilities:      string  &log;
		## Negotiate context types, in wire order (SMB 3.1.1 only).
		neg_context_types: string  &log;
		## Encryption ciphers (SMB 3.1.1 only).
		ciphers:           string  &log;
		## Compression algorithms (SMB 3.1.1 only).
		compression:       string  &log;
		## Signing algorithms (SMB 3.1.1 only).
		signing:           string  &log;
		## NTLMSSP NegotiateFlags (NTLM authentication only).
		ntlmssp_flags:     string  &log;
		## Client label from smbfp::known_clients, if the fingerprint is known.
		client:            string  &log &optional;
	};

	global log_smbfp: event(rec: Info);

	## Stop looking for the NEGOTIATE and NTLMSSP messages after this many
	## bytes of client data.
	const max_scan_bytes = 65536 &redef;

	redef enum Intel::Where += {
		SMB::IN_FP_EXT,
	};
}

redef record SMB::FileInfo += {
	smbfp_ext: string &log &optional;
};

redef record SMB::TreeInfo += {
	smbfp_ext: string &log &optional;
};

redef tcp_content_delivery_ports_orig += {
	[139/tcp] = T,
	[445/tcp] = T,
};

type State: record {
	buf:          string &default="";
	scanned:      count  &default=0;
	done:         bool   &default=F;
	have_neg:     bool   &default=F;
	have_ntlm:    bool   &default=F;
	ts:           time   &optional;
	dialects:     string &default="";
	capabilities: string &default="";
	ctx_types:    string &default="";
	ciphers:      string &default="";
	compression:  string &default="";
	signing:      string &default="";
	ntlm_flags:   string &default="";
	## Client data was lost before the fingerprint was complete.
	gap:          bool   &default=F;
	## Sequence number expected for the next chunk of client data.
	next_seq:     count  &optional;
	## The fingerprint, once logged.
	fp:           string &optional;
};

redef record connection += {
	smbfp_ext: State &optional;
};

const SMB2_DIALECT_311 = 0x0311;

# Little-endian readers with 0-based offsets. Callers check bounds.
function u8(s: string, off: count): count
	{
	return bytestring_to_count(sub_bytes(s, off + 1, 1));
	}

function u16(s: string, off: count): count
	{
	return bytestring_to_count(sub_bytes(s, off + 1, 2), T);
	}

function u32(s: string, off: count): count
	{
	return bytestring_to_count(sub_bytes(s, off + 1, 4), T);
	}

# Reads count uint16 values starting at off, formatted as 4-digit hex.
function hex16_list(s: string, off: count, n: count, end: count): string
	{
	local v: vector of string = vector();
	local i = 0;

	while ( i < n && off + 2 * i + 2 <= end )
		{
		v += fmt("%04x", u16(s, off + 2 * i));
		++i;
		}

	return join_string_vec(v, ",");
	}

function parse_negotiate(s: State, msg: string)
	{
	# Body directly follows the 64-byte SMB2 header.
	local b = 64;
	if ( |msg| < b + 36 )
		return;

	local dialect_count = u16(msg, b + 2);
	if ( |msg| < b + 36 + 2 * dialect_count )
		return;

	s$dialects = hex16_list(msg, b + 36, dialect_count, |msg|);
	s$capabilities = fmt("%x", u32(msg, b + 8));
	s$have_neg = T;

	local has_311 = F;
	local i = 0;
	while ( i < dialect_count )
		{
		if ( u16(msg, b + 36 + 2 * i) == SMB2_DIALECT_311 )
			has_311 = T;
		++i;
		}

	# NegotiateContextOffset/Count only exist when 3.1.1 is offered;
	# otherwise these bytes are ClientStartTime.
	if ( ! has_311 )
		return;

	local off = u32(msg, b + 28);
	local ctx_count = u16(msg, b + 32);
	local types: vector of string = vector();
	local ciphers = "";
	local compression = "";
	local signing = "";

	i = 0;
	while ( i < ctx_count )
		{
		# Contexts are 8-byte aligned relative to the SMB2 header.
		off = (off + 7) / 8 * 8;
		if ( off + 8 > |msg| )
			break;

		local ctx_type = u16(msg, off);
		local data = off + 8;
		local data_end = data + u16(msg, off + 2);
		types += fmt("%04x", ctx_type);

		if ( data_end > |msg| )
			break;

		if ( ctx_type == 0x0002 && data + 2 <= data_end )
			ciphers = hex16_list(msg, data + 2, u16(msg, data), data_end);
		else if ( ctx_type == 0x0003 && data + 8 <= data_end )
			compression = hex16_list(msg, data + 8, u16(msg, data), data_end);
		else if ( ctx_type == 0x0008 && data + 2 <= data_end )
			signing = hex16_list(msg, data + 2, u16(msg, data), data_end);

		off = data_end;
		++i;
		}

	s$ctx_types = join_string_vec(types, ",");
	s$ciphers = ciphers;
	s$compression = compression;
	s$signing = signing;
	}

function find_ntlmssp_negotiate(s: State, msg: string)
	{
	local rest = msg;

	while ( T )
		{
		local idx = strstr(rest, "NTLMSSP\x00");
		if ( idx == 0 )
			return;

		local start = idx - 1;
		if ( start + 16 > |rest| )
			return;

		if ( u32(rest, start + 8) == 1 )
			{
			s$ntlm_flags = fmt("%08x", u32(rest, start + 12));
			s$have_ntlm = T;
			return;
			}

		rest = sub_bytes(rest, idx + 8, |rest|);
		}
	}

function finish(c: connection)
	{
	local s = c$smbfp_ext;
	if ( s$done )
		return;

	s$done = T;
	s$buf = "";

	# Pure SMB1 connections are covered by the legacy fingerprint only.
	if ( ! s$have_neg )
		return;

	# A gap in the client stream before this point may have swallowed a
	# NEGOTIATE or SESSION_SETUP message, so the features may be incomplete.
	if ( s$gap )
		{
		Reporter::conn_weird("smbfp_content_gap", c, "", "smbfp");
		return;
		}

	local fp_str = join_string_vec(vector(s$dialects, s$capabilities, s$ctx_types,
	                                      s$ciphers, s$compression, s$signing,
	                                      s$ntlm_flags), ";");
	local fp = md5_hash(fp_str);

	s$fp = fp;

	local info = Info($ts=s$ts, $uid=c$uid, $id=c$id,
	                  $fingerprint=fp, $fingerprint_str=fp_str,
	                  $dialects=s$dialects, $capabilities=s$capabilities,
	                  $neg_context_types=s$ctx_types, $ciphers=s$ciphers,
	                  $compression=s$compression, $signing=s$signing,
	                  $ntlmssp_flags=s$ntlm_flags);

	if ( fp in known_clients )
		info$client = known_clients[fp];

	Log::write(smbfp::LOG, info);

	Intel::seen(Intel::Seen($indicator=fp, $indicator_type=Intel::SMBFP,
	                        $conn=c, $where=SMB::IN_FP_EXT));
	}

function process_message(c: connection, msg: string)
	{
	local s = c$smbfp_ext;
	local proto = sub_bytes(msg, 1, 4);

	# Encrypted (transform) or compressed messages: the session
	# establishment is over.
	if ( proto == "\xfdSMB" || proto == "\xfcSMB" )
		{
		finish(c);
		return;
		}

	# SMB1, including the multi-protocol negotiate, is skipped.
	if ( proto != "\xfeSMB" || |msg| < 64 )
		return;

	local cmd = u16(msg, 12);

	if ( cmd == 0 )
		{
		if ( ! s$have_neg )
			{
			s$ts = network_time();
			parse_negotiate(s, msg);
			}
		}
	else if ( cmd == 1 )
		{
		find_ntlmssp_negotiate(s, msg);
		if ( s$have_ntlm )
			finish(c);
		}
	else
		# Any other command follows the session setup, e.g. under
		# Kerberos where no NTLMSSP message appears.
		finish(c);
	}

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
	{
	if ( ! is_orig )
		return;

	if ( ! c?$smbfp_ext )
		c$smbfp_ext = State();

	local s = c$smbfp_ext;
	if ( s$done )
		return;

	# Zeek does not raise content_gap for every hole (e.g. not when the
	# SYN-ACK was missed), so also check that the client data is contiguous.
	if ( s?$next_seq && seq != s$next_seq )
		s$gap = T;
	s$next_seq = seq + |contents|;

	s$buf = s$buf + contents;

	# Split into NetBIOS session service / direct TCP frames:
	# 1 byte type, 3 bytes big-endian length.
	while ( ! s$done && |s$buf| >= 4 )
		{
		local len = u8(s$buf, 1) * 65536 + u8(s$buf, 2) * 256 + u8(s$buf, 3);
		if ( |s$buf| < 4 + len )
			break;

		local frame_type = u8(s$buf, 0);
		local msg = sub_bytes(s$buf, 5, len);
		s$buf = sub_bytes(s$buf, 5 + len, |s$buf|);
		s$scanned += 4 + len;

		if ( frame_type == 0 )
			process_message(c, msg);
		}

	if ( ! s$done && s$scanned + |s$buf| > max_scan_bytes )
		finish(c);
	}

event content_gap(c: connection, is_orig: bool, seq: count, length: count)
	{
	if ( ! is_orig || c$id$resp_p !in tcp_content_delivery_ports_orig )
		return;

	if ( ! c?$smbfp_ext )
		c$smbfp_ext = State();

	if ( ! c$smbfp_ext$done )
		c$smbfp_ext$gap = T;
	}

event connection_state_remove(c: connection) &priority=10
	{
	if ( c?$smbfp_ext )
		finish(c);
	}

# Copy the fingerprint into the file and tree records of every SMB2 command,
# after the base scripts have selected them (priority 5), so that it stays
# with the records for the lifetime of the connection.
event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=4
	{
	if ( ! c?$smbfp_ext || ! c$smbfp_ext?$fp )
		return;

	if ( c$smb_state?$current_file )
		c$smb_state$current_file$smbfp_ext = c$smbfp_ext$fp;

	if ( c$smb_state?$current_tree )
		c$smb_state$current_tree$smbfp_ext = c$smbfp_ext$fp;
	}

event zeek_init() &priority=5
	{
	Log::create_stream(smbfp::LOG, Log::Stream($columns=Info, $ev=log_smbfp,
	                                           $path="smbfp", $policy=log_policy));
	}
