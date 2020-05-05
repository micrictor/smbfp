
SMBFP
SMB Fingerprinting Zeek package
=================================

## Purpose
This package will generate a fingerprint based upon observed values from the SMB negotation process, in a similar fashion to JA3 for TLS. This may be used to generate alerts for known-bad fingerprints (blacklist), as well as identify abnormal SMB clients (whitelist).

*WARNING* _Fingerprints generated may change in a future release_. At this time, this package is still incredibly bleeding edge, and I continue to refine which fields are used to generate the fingerprint. 

## Fields used to generate fingerprint
In order to fingerprint SMB clients, I had to determine which fields could possibly change based on the client software used. 
 

SMB1 Fields used:
 
* dialects - Strings that declare what versions of SMB the client supports
* max_buffer_len - Maxiumum buffer size for SMB messages supported by the client
* max_mpx_count - Maximum amount of open SMB commands the client supports at a single time (mpx = multiplex)
* native_os - A string that describes the OS of the client; Similar to an HTTP User Agent.
* native_lanman - The client's native LAN Manager type; Essentially the same as above
* primary_domain - The primary domain as specified by the client; rarely set
* capabilities.unicode - Whether or not the client supports unicode; Interesting because Windows clients always do
* capabilities.level_2_oplocks - Whether or not the client supports read-only opportunistic locking; default on in Windows since XP 
 
SMB2 Fields used:

* dialects - Integers that declare what versions of SMB the client supports

## TODO

* Submit patch to Zeek to include capabilities in smb2_negotiate_request event