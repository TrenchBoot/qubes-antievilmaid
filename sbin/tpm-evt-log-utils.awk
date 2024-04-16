# This file contains a set of utility functions common for TPM1.2 and 2.0

function assert(condition, string)
{
	if (!condition) {
		print string
		exit 1
	}
}

function ord_init(    _i)
{
	for (_i = 0; _i < 256; _i++) {
		ord[sprintf("%c", _i)] = _i
	}
}

function x2n(hex, width,    _i)
{
	mult = 1
	num = 0
	for (_i = 0; _i < width; _i++) {
		num += ord[substr(hex, _i+1, 1)] * mult
		mult *= 256
	}
	return num
}

function hex_noprint(hex, len,    _i, _str)
{
	_str = ""
	for (_i = 0; _i < len; _i++) {
		_str = _str sprintf("%02x", ord[substr(hex, _i+1, 1)])
	}
	return _str
}

function hexdump(hex, len)
{
	print hex_noprint(hex, len)
}

function alg_name(id)
{
	switch (id) {
		case 0x0004: return "SHA1"
		case 0x000b: return "SHA256"
		case 0x000c: return "SHA384"
		case 0x000d: return "SHA512"
		case 0x0012: return "SM3-256"
		case 0x0027: return "SHA3-256"
		case 0x0028: return "SHA3-384"
		case 0x0029: return "SHA3-512"
		default: return sprintf("unknown (%#06x)", id)
	}
}

function string_or_hex(str, len)
{
	_len = len
	if (_len > 128)
		_len = 128
	# String must start with a series of printable characters ...
	if (match(str, "[[:graph:][:blank:]]*", a) != 1) {
		hexdump(str, _len)
	# ... long until the end, with "optional" (i.e. bad implementation) \0.
	} else if (len != a[0, "length"] &&
		   (len != a[0, "length"] + 1 || index(str, "\0") != len)) {
		hexdump(str, _len)
	} else
		printf("%.*s\n", _len, a[0])
	if (_len != len)
		printf("... (event truncated to %d first bytes, was %d)\n", _len, len)
}

function replay_sha(vals, len, c,    val, _i, n, arr, cmd)
{
	val = sprintf("%0" len "." len "x", 0)
	n = split(vals, arr, "\n")
	for (_i = 1; _i < n; _i++) {
		cmd = "echo " val arr[_i] " | xxd -r -p | " c " > /tmp/sha"
		system(cmd)
		getline val <"/tmp/sha"
		close("/tmp/sha")
		close(cmd)
		# Drop trailing file name and newline character
		val = substr(val, 1, len)
	}
	system("rm /tmp/sha")
	print val
}

function replay_sha1(pcr)
{
	printf "    %d: ", pcr
	replay_sha(SYMTAB["SHA1_" pcr], 40, "sha1sum")
}

function replay_sha256(pcr)
{
	printf "    %d: ", pcr
	replay_sha(SYMTAB["SHA256_" pcr], 64, "sha256sum")
}
