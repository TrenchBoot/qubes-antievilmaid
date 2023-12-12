#!/usr/bin/gawk -bf
@load "readfile"

function assert(condition, string)
{
	if (!condition) {
		print string
		exit 1
	}
}

function ord_init()
{
	for (_i = 0; _i < 256; _i++) {
		ord[sprintf("%c", _i)] = _i
	}
}

function x2n(hex, width)
{
	mult = 1
	num = 0
	for (_i = 0; _i < width; _i++) {
		num += ord[substr(hex, _i+1, 1)] * mult
		mult *= 256
	}
	return num
}

function hexdump(hex, len)
{
	for (_i = 0; _i < len; _i++) {
		printf("%02x", ord[substr(hex, _i+1, 1)])
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
		printf("%.*s", _len, a[0])
	if (_len != len)
		printf("... (event truncated to %d first bytes, was %d)", _len, len)
}

BEGIN {
	PROCINFO["readfile"]
	FIELDWIDTHS = "20 12 1 1 1 1 4 4 4 *"
	ord_init()
}
{
	# Header sanity checks
	assert($1 == "TXT Event Container\0", "Bad TXT Event Container signature")
	assert(match($2, "\0{12}"), "Reserved field is not all 0")
	assert($3 == "\1", "Bad container major version")
	# Minor version is bumped if there are compatible changes like new
	# fields added to the end of structure. Header stores offset to PCR
	# events so those new fields can be skipped.
	#assert($4 == "\0", "Bad container minor version")
	assert($5 == "\1", "Bad event structure major version")
	# There is no field that would specify size of whole event structure,
	# any new fields added to it would break this parser.
	assert($6 == "\0", "Bad event structure minor version")
	assert(x2n($7, 4) == length(), "Bad container size")
	assert(x2n($8, 4) >= (20+12+1+1+1+1+4+4+4), "PCR Event offset too small")
	assert(x2n($9, 4) > x2n($8, 4), "Next Event offset too small")
	FIELDWIDTHS="4 4 20 4 *"
	$0 = substr($0, x2n($8, 4) + 1)
}
{
	entry = 0
	printf("\n")
	while (NF > 0) {
		if ($2 == "\0\0\0\0") break
		printf("Entry %d:\n", ++entry)
		printf("    PCR:        %d\n", x2n($1, 4))
		printf("    Event Type: %#x\n", x2n($2, 4))
		printf("    Digests:\n")
		printf("      SHA1: ")
		hexdump($3, 20)
		printf("\n")
		printf("    Event: ")
		string_or_hex($5, x2n($4, 4))
		printf("\n\n")
		$0 = substr($5, x2n($4, 4) + 1)
	}
}
