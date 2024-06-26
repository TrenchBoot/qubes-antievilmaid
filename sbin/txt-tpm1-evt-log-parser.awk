#!/usr/bin/gawk -bf
@load "readfile"
@include "/sbin/tpm-evt-log-utils.awk"

BEGIN {
	PROCINFO["readfile"]
	# Start by assuming presence of a TCG-compatible header
	FIELDWIDTHS = "4 4 20 4 16 4 1 1 1 1 1 *"
	ord_init()
	SHA1_17 = ""
	SHA1_18 = ""
	SHA1_255 = ""
}
{
	# TCG header is not present on Intel systems, so do nothing if it's not
	# there (is "Spec ID Event01\0" value possible too?)
	tcg_prefix_size = 0
	if ($5 == "Spec ID Event00\0" || $5 == "Spec ID Event02\0") {
		# TXT length field includes length of TCG header
		tcg_prefix_size = 4+4+20+4+16+4+1+1+1+1+1

		# TCG header sanity checks
		assert($1 == "\0\0\0\0", "Bad PCR index for log header")
		assert($2 == "\3\0\0\0", "Bad event type for log header")
		assert(match($3, "\0{20}"), "Bad digest for log header")
		assert(x2n($4, 4) >= (16+4+1+1+1+1+4+2+2+1), "Bad SpecIDEvent length")
		assert($6 == "\1\0\0\0" || $6 == "\0\0\0\0", "Bad platform class")
		assert($7 == "\2", "Bad spec minor version")
		assert($8 == "\1", "Bad spec major version")
		# Revision 2 turned reserved field into a UINT field, both are versions
		# are handled. There should be no new revisions.
		assert(x2n($9, 1) <= 2, "Bad spec errata")
		# This field is reversed in 1.21, but UINTN in 1.22
		assert($10 == "\0" || $10 == "\1" || $10 == "\2", "Bad UINTN size")
		assert($11 == "\060", "Bad TXT header size")

		$0 = $12
	}

	# Assume TXT header now
	FIELDWIDTHS = "20 12 1 1 1 1 4 4 4 *"
	# Make AWK apply the new value of FIELDWIDTHS
	$0 = $0
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
	assert(x2n($7, 4) == length() + tcg_prefix_size, "Bad container size")
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
		sym = "SHA1_" x2n($1, 4)
		SYMTAB[sym] = SYMTAB[sym] hex_noprint($3, 20) "\n"
		printf("    Event: ")
		string_or_hex($5, x2n($4, 4))
		printf("\n")
		$0 = substr($5, x2n($4, 4) + 1)
	}
	print "Expected PCR values:"
	replay_sha1(17)
	replay_sha1(18)
}
