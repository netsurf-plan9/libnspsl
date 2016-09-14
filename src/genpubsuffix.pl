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
    
    print "static const char stab[" . $$stridx_ref . "] = {\n";
    while ( my ($key, $value) = each(%$strtab_ref) ) {
    #for (@domelem_array) {
#	my $key = $_;
#	my $value = $strtab_ref->{$key};
	print "    " . phexstr($key) . "/* " . $key . " " . $value . " */\n";
    }
    print "};\n\n";
}

sub phexstr
{
    use bytes;

    my ($str) = @_;
    my $ret;

    my @bytes = unpack('C*', $str);

    #$ret = $ret . sprintf("0x%02x, ", scalar(@bytes));

    foreach (@bytes) {
	$ret = $ret . sprintf("0x%02x, ", $_);
    }

    return $ret;
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
    $$opidx_ref += scalar keys %$parent_ref;

    # entry block 
    if ($startidx == ($$opidx_ref - 1)) {
	$our_dat = "\n    /* entry " . $startidx . " */\n    ";
    } else {
	$our_dat = "\n    /* entries " . $startidx . " to " . ($$opidx_ref - 1) . " */\n    ";
    }

    # iterate over each child element domain/ref pair
    while ( my ($cdom, $cref) = each(%$parent_ref) ) {
        # make array look pretty by limiting entries per line
	if ($lineidx == 3) {
	    $our_dat .= "\n    ";
	    $lineidx = 0;
	} elsif ($lineidx == -1) {
	    $lineidx = 1;
	} else {
	    $our_dat .= " ";
	    $lineidx += 1;
	}

	$our_dat .= "{ ";
	$our_dat .= $strtab_ref->{$cdom} . ", ";
	my $child_count = scalar keys (%$cref);
	$our_dat .= $child_count . ", ";
	if ($child_count != 0) {
	    $our_dat .= $$opidx_ref . ", ";
	    $child_dat .= calc_pnode($cref, $strtab_ref, $opidx_ref);
	} else {
	    $our_dat .= 0 . ", ";
	}
	$our_dat .= pstr_len($cdom) ;
	$our_dat .= " },";

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

print "struct pnode {\n";
print "    uint16_t label; /**< index of domain element in string table */\n";
print "    uint16_t child_count; /* number of children of this node */\n";
print "    uint16_t child_index; /**< index of first child node */\n";
print "    uint8_t label_len; /**< length of domain element in string table */\n";
print "};\n\n";

my $opidx = 1; # output index of node

print "static const struct pnode pnodes[" . $nodeidx . "] = {\n";

# root node
print "    /* root entry */\n"; 
print "    { 0, " . scalar keys(%tldtree) . ", " . $opidx . ", 0 },"; 

# all subsequent nodes
print calc_pnode(\%tldtree, \%strtab, \$opidx);
print "\n};\n\n";
