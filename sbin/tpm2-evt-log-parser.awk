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
		printf("%.*s", _len, a[0])
	if (_len != len)
		printf("... (event truncated to %d first bytes, was %d)", _len, len)
}

BEGIN {
	PROCINFO["readfile"]
	FIELDWIDTHS = "4 4 20 4 16 4 1 1 1 1 4 *"
	ord_init()
}
{
	# Header sanity checks
	assert($1 == "\0\0\0\0", "Bad PCR index for log header")
	assert($2 == "\3\0\0\0", "Bad event type for log header")
	assert(match($3, "\0{20}"), "Bad digest for log header")
	assert(x2n($4, 4) >= (16+4+1+1+1+1+4+2+2+1), "Bad SpecIDEvent length")
	assert($5 == "Spec ID Event03\0", "Bad SpecIDEvent signature")
	assert($6 == "\1\0\0\0" || $6 == "\0\0\0\0", "Bad platform class")
	assert($7 == "\0", "Bad spec minor version")
	assert($8 == "\2", "Bad spec major version")
	# So far there were no functional changes between revisions, only field
	# names were changed. Uncomment the following if it any compatibility
	# breaking change is made.
	#assert(x2n($9, 1) <= 106, "Bad spec errata")
	assert($10 == "\1" || $10 == "\2", "Bad UINTN size")
	num_algo = x2n($11, 4)
	assert(num_algo > 0, "No algorithms specified")
	FIELDWIDTHS="2 2 *"
	$0 = $12
}
{
	# Iterate over algorithm sizes, save for later
	print "Found " num_algo " algorithms:"
	# num_algo IDs, 2 bytes each
	digests_size = 2*num_algo
	for (i = 0; i < num_algo; i++) {
		alg[i] = x2n($1, 2) SUBSEP x2n($2, 2)
		printf("    ID %#06x size = %#x\n", x2n($1, 2), x2n($2, 2))
		digests_size += x2n($2, 2)
		$0 = $3
	}
	vendorInfoSize = x2n($0, 1)
	print "vendorInfoSize = " vendorInfoSize
	FIELDWIDTHS=sprintf("4 4 4 %d 4 *", digests_size)
	$0 = substr($0, vendorInfoSize+2)
}
{
	entry = 0
	printf("\n")
	while (NF > 0) {
		if ($3 == "\0\0\0\0") break
		printf("Entry %d:\n", ++entry)
		printf("    PCR:        %d\n", x2n($1, 4))
		printf("    Event Type: %#x\n", x2n($2, 4))
		printf("    Digests:\n")
		assert(x2n($3, 4) == num_algo, "Bad number of algorithms")
		for (i = 0; i < num_algo; i++) {
			split(alg[i], a, SUBSEP)
			assert(x2n($4, 2) == a[1], "Bad digest algorithm")
			$4 = substr($4, 3)
			printf("      %s: ", alg_name(a[1]))
			hexdump($4, a[2])
			printf("\n")
			$4 = substr($4, a[2]+1)
		}
		printf("    Event: ")
		string_or_hex($6, x2n($5, 4))
		printf("\n\n")
		$0 = substr($6, x2n($5, 4) + 1)
	}
}
