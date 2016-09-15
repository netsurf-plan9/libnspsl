#
# Public suffix C include generator
#
# Copyright 2016 Vincent Sanders <vince@kyllikki.og>
#
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all
# copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
# OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.


# This program converts the public suffix list data [1] into a C
#  program with static data representation and acessor function.
#
# The actual data list [2] should be placed in a file effective_tld_names.dat
#
# The C program is written to stdout, the typical 160K input file
#  generates 500K of program and compiles down to a 100K object file
#
# There is a single exported function
#
# const char *getpublicsuffix(const char *hostname)
# 
# This returns the public suffix of the passed hostname or NULL if
#  there was an error processing the hostname. The returned pointer is
#  within the passed hostname so if the returned pointer is the same as
#  hostname the whole hostname is a public suffix otherwise the passed
#  hostname has a private part.
#
# The resulting C file is mearly a conversion of the input data (the
#  added c code is from this source and licenced under the same terms)
#  and imposes no additional copyright above that of the source data
#  file.
#
# Note: The pnode structure is built assuming there will never be more
#  label nodes than can fit in an unsigned 16 bit value (65535) but as
#  there are currently around 8000 nodes there is space for another
#  58,000 before this becomes an issue.
#
# [1] https://publicsuffix.org/
# [2] https://publicsuffix.org/list/effective_tld_names.dat


# debian package for ordered hashes: libtie-ixhash-perl
# debian package for punycode encode: libidna-punycode-perl

use strict;
use warnings;
use utf8;
use Tie::IxHash;
use IDNA::Punycode;

sub treesubdom
{
    my ($tldtree_ref, $nodeidx_ref, $strtab_ref, $stridx_ref, $parts_ref) = @_;

    my $domelem = pop @{$parts_ref}; # Doamin element
    my $isexception = 0;
    tie my %node, 'Tie::IxHash'; # this nodes hash

    # deal with explicit domain exceptions 
    $isexception = ($domelem =~ s/\A!//);
    if ($isexception != 0) {
	$node{"!"} = {};
	$$nodeidx_ref += 1;
    }
    my $domelem_puny = encode_punycode($domelem);

    # Update string table
    if (! exists $strtab_ref->{$domelem_puny}) {
	# add to string table
	$strtab_ref->{$domelem_puny} = $$stridx_ref;
	{
	    use bytes;
	    # update the character count index
	    $$stridx_ref += length($domelem_puny);
	}
	
    }

    # link new node list into tree
    if (! exists $tldtree_ref->{$domelem_puny}) {
	$tldtree_ref->{$domelem_puny} = \%node;
	$$nodeidx_ref += 1;
    }

    # recurse down if there are more parts to the domain
    if (($isexception == 0) && (scalar(@{$parts_ref}) > 0)) {
	treesubdom($tldtree_ref->{$domelem_puny}, $nodeidx_ref, $strtab_ref, $stridx_ref, $parts_ref);
    }
}

# output an array of bytes in hex
sub phexstr
{
    use bytes;

    my ($str) = @_;
    my $ret;

    my @bytes = unpack('C*', $str);
    my $count = 0;
    my $txt = "";

    foreach (@bytes) {
	$ret = $ret . sprintf("0x%02x, ", $_);
	$txt = $txt . sprintf("%c", $_);
	$count += 1;
	if ($count == 8) {
	    $ret = $ret . " /* " . $txt . " */\n    ";
	    $count = 0;
	    $txt="";
	}
    }

    if ($count != 0) {
	$ret = $ret . " /* " . $txt . " */\n";
    }

    return $ret;
}


# output string table
#
# array of characters the node table below directly indexes entries.
sub generate_string_table
{
    my ($tldtree_ref, $nodeidx_ref, $strtab_ref, $stridx_ref) = @_;

    my @tmp_array;

    foreach my $keys (keys %$strtab_ref) {
	push(@tmp_array, $keys);
    }

    my @domelem_array = sort { length($b) <=> length($a) } @tmp_array;

    my $stringtable = "*!"; # table being generated
    my $stringtablesize = 2;
    for my $domelem (@domelem_array) {
	my $substridx = index($stringtable, $domelem);
	if ($substridx != -1) {
	    # found existing string match so use it
	    $strtab_ref->{$domelem} = $substridx;
	} else {
	    $strtab_ref->{$domelem} = $stringtablesize;
	    $stringtable .= $domelem;
	    {
		use bytes;
		$stringtablesize += length($domelem);
	    }
	}
    }
    print "static const char stab[" . $stringtablesize . "] = {\n";
    print "    " . phexstr($stringtable);
    print "};\n\n";
}


# Output the length of the string
sub pstr_len
{
    use bytes;

    my ($str) = @_;
    my $ret;

    my @bytes = unpack('C*', $str);

    $ret = $ret . sprintf("%d", scalar(@bytes));

    return $ret;
}

# generate all the children of a parent node and recurse into each of
#  those updating optidx to point to the next free node
sub calc_pnode 
{
    my ($parent_ref, $strtab_ref, $opidx_ref) = @_;
    my $our_dat;
    my $child_dat = "";
    my $startidx = $$opidx_ref;
    my $lineidx = -1;

    # update the output index to after this node
    # need to allow for an additional node for each entry with children

    # iterate over each child element domain/ref pair
    while ( my ($cdom, $cref) = each(%$parent_ref) ) {
	if (scalar keys (%$cref) != 0) {
	    $$opidx_ref += 2;
	} else {
	    $$opidx_ref += 1;
	}
    }

    # entry block 
    if ($startidx == ($$opidx_ref - 1)) {
	$our_dat = "\n    /* entry " . $startidx . " */\n";
    } else {
	$our_dat = "\n    /* entries " . $startidx . " to " . ($$opidx_ref - 1) . " */\n";
    }

    # iterate over each child element domain/ref pair
    while ( my ($cdom, $cref) = each(%$parent_ref) ) {
	my $child_count = scalar keys (%$cref);

	$our_dat .= "    { ";
	$our_dat .= ".label = {" . $strtab_ref->{$cdom} . ", ". pstr_len($cdom) ;
	if ($child_count == 0) {
	    # complete label for no children
	    $our_dat .= ", 0 } },\n";
	} else {
	    # complete label with children
	    $our_dat .= ", 1 } }, ";
	    $our_dat .= "{ .child = { " . $$opidx_ref . ", " . $child_count . " } },\n";
	    $child_dat .= calc_pnode($cref, $strtab_ref, $opidx_ref);
	}
    }

    return $our_dat . $child_dat;
}

# main
binmode(STDOUT, ":utf8");

my ($filename) = @ARGV;

if (not defined $filename) {
    die "need filename\n";
}

open(my $fh, '<:encoding(UTF-8)', $filename)
    or die "Could not open file '$filename' $!";

tie my %tldtree, 'Tie::IxHash'; # node tree
my $nodeidx = 1; # count of nodes allowing for the root node

tie my %strtab, 'Tie::IxHash'; # string table
my $stridx = 0;

# put the wildcard match at 0 in the string table
$strtab{'*'} = $stridx;
$stridx += 1;

# put the invert match at 1 in the string table
$strtab{'!'} = $stridx;
$stridx += 1;

# read each line from prefix data and inject into hash tree
while (my $line = <$fh>) {
    chomp $line;

    if (($line ne "") && ($line !~ /\/\/.*$/)) {

	# print "$line\n";
	my @parts=split("\\.", $line);

	# recusrsive call to build tree from root

	treesubdom(\%tldtree, \$nodeidx, \%strtab, \$stridx, \@parts);
    }
}

# C program header
print <<EOF;
/*
 * Generated with the genpubsuffix tool from effective_tld_names.dat
 */

EOF

generate_string_table(\%tldtree, \$nodeidx, \%strtab, \$stridx);

print "enum stab_entities {\n";
print "    STAB_WILDCARD = 0,\n";
print "    STAB_EXCEPTION = 1\n";
print "};\n\n";


# output static node array
#
# The constructed array of nodes has all siblings sequentialy and an
# index/count to its children. This yeilds a very compact data
# structure easily traversable.
#
# Additional flags for * (match all) and ! (exception) are omitted as
# they can be infered by having a node with a label of 0 (*) or 1 (!)
# as the string table has those values explicitly created.
#
# As labels cannot be more than 63 characters a byte length is more
# than sufficient.


my $opidx = 2; # output index of node
my $opnodes = ""; # output pnode initialisers

# root node initialiser
$opnodes .= "    /* root entry */\n";
$opnodes .= "    { .label = { 0, 0, 1 } }, { .child = { " . $opidx . ", " . scalar keys(%tldtree) . " } },";

# generate node initialiser
$opnodes .= calc_pnode(\%tldtree, \%strtab, \$opidx);


print "union pnode {\n";
print "    struct {\n";
print "        uint16_t idx; /**< index of domain element in string table */\n";
print "        uint8_t len; /**< length of domain element in string table */\n";
print "        uint8_t children; /**< has children */\n";
print "    } label;\n";
print "    struct {\n";
print "        uint16_t index; /**< index of first child node */\n";
print "        uint16_t count; /* number of children of this node */\n";
print "    } child;\n";
print "};\n\n";

print "static const union pnode pnodes[" . $opidx . "] = {\n";

# output node initialisors
print $opnodes;

print "\n};\n\n";
