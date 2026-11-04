
SMBFP
SMB Fingerprinting Zeek package
=================================

## Purpose
This package will generate a fingerprint based upon observed values from the SMB negotiation process, in a similar fashion to JA3 for TLS. This may be used to generate alerts for known-bad fingerprints (blacklist), as well as identify abnormal SMB clients (whitelist).

The package produces two fingerprints:

* `smbfp_cl` - the original fingerprint, for SMB1 clients
* `smbfp_ext` - an extended fingerprint for SMB2/3 clients

## Fields used to generate fingerprint
In order to fingerprint SMB clients, I had to determine which fields could possibly change based on the client software used. 

### SMB1 (`smbfp_cl`)

* dialects - Strings that declare what versions of SMB the client supports
* max_buffer_len - Maximum buffer size for SMB messages supported by the client
* max_mpx_count - Maximum amount of open SMB commands the client supports at a single time (mpx = multiplex)
* native_os - A string that describes the OS of the client; Similar to an HTTP User Agent.
* native_lanman - The client's native LAN Manager type; Essentially the same as above
* primary_domain - The primary domain as specified by the client; rarely set
* capabilities.unicode - Whether or not the client supports unicode; Interesting because Windows clients always do
* capabilities.level_2_oplocks - Whether or not the client supports read-only opportunistic locking; default on in Windows since XP 

### SMB2/3 (`smbfp_ext`)

All features come from the session establishment, which stays unencrypted even when SMB3 encryption is
active. Seven features are joined with `;` and hashed with MD5:

```
Dialects;Capabilities;NegContextTypes;Ciphers;Compression;Signing;NtlmsspFlags
```

* Dialects - dialects offered in the first SMB2 NEGOTIATE request, in wire order
* Capabilities - Capabilities field of the NEGOTIATE request
* NegContextTypes - types of all negotiate contexts, in wire order (SMB 3.1.1)
* Ciphers - encryption ciphers from the ENCRYPTION_CAPABILITIES context (SMB 3.1.1)
* Compression - algorithms from the COMPRESSION_CAPABILITIES context (SMB 3.1.1)
* Signing - algorithms from the SIGNING_CAPABILITIES context (SMB 3.1.1)
* NtlmsspFlags - NegotiateFlags of the first NTLMSSP NEGOTIATE message in a SESSION_SETUP request (NTLM only).

The SMB2/3 fingerprint implements the client identification methodology of the paper

> Carl Gadde and Jan-Niclas Hilgert. "Forensic Analysis of Encrypted SMB Traffic: Decryption, Client
> Identification and Event Reconstruction." *Digital Threats: Research and Practice*, 2026.
> https://doi.org/10.1145/3848131

## Output

* `smbfp_cl` (SMB1) and `smbfp_ext` (SMB2/3) columns in `smb_files.log` and `smb_mapping.log`
* `smbfp.log` (SMB2/3) - one line per connection with the hash (`fingerprint`), the hashed string
  (`fingerprint_str`) and every feature in its own column
* `client` column in `smbfp.log` with a label from `smbfp::known_clients` (`scripts/smbfp-clients.zeek`)
  if the fingerprint is known, e.g. `Windows 11` or `smbclient 4.22`. Unknown fingerprints stay
  unset. Local entries can be added with `redef smbfp::known_clients += { ["<md5>"] = "<label>" };`
* `Intel::seen` for both fingerprints (type `Intel::SMBFP`, location `SMB::IN_FP` or `SMB::IN_FP_EXT`),
  so hashes listed in `scripts/smbfp.intel` show up in `intel.log`

## Limitations

A matching fingerprint does not prove that the connection came from the labelled client or version.
The `client` label only means that the observed negotiation is identical to that of a client tested in
the lab. A fingerprint is a hash of a few negotiation parameters, not a unique identifier: Different
clients and versions can produce the same fingerprint, e.g. all Windows applications on one Windows
version. Untested versions may match a known fingerprint as well.

Treat the label as a hint that has to be corroborated with other evidence.
