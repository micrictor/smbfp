##! Known SMB2/3 client implementations by extended fingerprint.
##! A fingerprint identifies the SMB implementation, not the application
##! (all Windows applications share one per Windows version). Labels are
##! only hints, see Limitations in the README.
##!
##! Local entries: redef smbfp::known_clients += { ["<md5>"] = "<label>" };

module smbfp;

export {
	## Maps extended fingerprints to client labels.
	const known_clients: table[string] of string = {
		# Windows (mrxsmb20.sys)
		["d4d2c4422e94e51df337049ae5004b67"] = "Windows 11",
		["17a9d4b69447925b757f07a2c3c9400f"] = "Windows 10",
		["46904e4ac9dcb477c655edf779187277"] = "Windows 8",

		# Samba smbclient
		["52d7d0be7895fb96e9d90b54c5bd6f76"] = "smbclient 4.22",
		["1799d5285377e5b2631e304a50e74803"] = "smbclient 4.15-4.19",

		# C# SMBLibrary
		["2550bedd3c2dc9dd4456d1f0fdca009c"] = "SMBLibrary 1.5.5.1 (C#)",
		["507ecc33a233af81e99d261ad1ef082b"] = "SMBLibrary 1.5.5 (C#)",
		["dfdac8835f9fe35c24d00977a658c756"] = "SMBLibrary 1.4.3 (C#)",

		# Go go-smb2
		["06602a67b9f39873afa219cfbf1ac336"] = "go-smb2 1.0.0-1.1.0 (Go)",

		# Java SMBJ
		["8ac361f197158c4e93e9c52aff3579bb"] = "SMBJ 0.13.0-0.14.0 (Java)",
		["266223dbb1863a654467f388b8274b50"] = "SMBJ 0.11.3 (Java)",

		# Python smbprotocol
		["f5b79148ce32025472592a96684549bc"] = "smbprotocol 1.14.0-1.15.0 (Python)",
		["c4a0baa728544079ffee3f72284b766e"] = "smbprotocol 1.5.0 (Python)",

		# Ruby ruby_smb
		["2be668c3401feb2d81ac2313093f1c5c"] = "ruby_smb 3.3.15-3.3.16 (Ruby)",
		["c33901e86db1b88e5c4bf9a9ff98e2bf"] = "ruby_smb 2.0.0 (Ruby)",
	} &redef;
}
