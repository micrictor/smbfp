
SMBFP
SMB Fingerprinting Zeek package
=================================

## Purpose
This package will generate a fingerprint based upon observed values from the SMB negotation process, in a similar fashion to JA3 for TLS. This may be used to generate alerts for known-bad fingerprints (blacklist), as well as identify abnormal SMB clients (whitelist).

## TODO

* Integrate with Intel framework
* Submit patch to Zeek to include capabilities in smb2_negotiate_request event