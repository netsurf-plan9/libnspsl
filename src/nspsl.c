/*
 * Copyright 2016 Vincent Sanders <vince@netsurf-browser.org>
 *
 * This file is part of libnspsl
 *
 * Licensed under the MIT License,
 *                http://www.opensource.org/licenses/mit-license.php
 */

#include <stdint.h>
#include <string.h>

#include "nspsl.h"

#include "psl.inc"

#define DOMSEP '.'

/**
 * Test whether a character is upper-case alphabetical.
 *
 * \param[in] c  Character to test.
 * \return true iff `c` is upper-case alphabetical, else false.
 */
static inline int ascii_is_alpha_upper(char c)
{
        return (c >= 'A' && c <= 'Z');
}

/**
 * Convert an upper case character to lower case.
 *
 * If the given character is not upper case alphabetical, it is returned
 * unchanged.
 *
 * \param[in] c  Character to convert.
 * \return lower case conversion of `c` else `c`.
 */
static inline char ascii_to_lower(char c)
{
        return (ascii_is_alpha_upper(c)) ? (c + 'a' - 'A') : c;
}

static int huffcasecmp(unsigned int labelidx, const char *str, unsigned int len)
{
        const uint8_t *stabidx; /* string table byte index */
        unsigned int bitidx; /* amount of current byte used */
        unsigned int cnt; /* current character being compared */
        uint8_t curc; /* current label table byte */
        unsigned int curh; /* current huffman tree node */
        int res;
        int term;

        /* get address of byte */
        stabidx = &stab[labelidx >> 3];
        /* offset of first bit */
        bitidx = labelidx & 7;

        curc = *stabidx; stabidx++;
        curc = curc >> bitidx;

        for (cnt = 0; cnt < len; cnt++) {
                /* walk huffman code table to get value */
                curh = 0;
                term = 0;
                while (term == 0) {
                        term = htable[curh + (curc & 1)].term;
                        curh = htable[curh + (curc & 1)].value;
                        bitidx++;
                        if (bitidx < 8) {
                                curc = curc >> 1;
                        } else {
                                curc = *stabidx; stabidx++;
                                bitidx = 0;
                        }
                }

                res = ascii_to_lower(str[cnt]) - curh;
                if (res != 0) {
                        return res;
                }
        }

        return 0;
}

/**
 * match the label element of the domain from a point in the tree
 */
static int matchlabel(int parent, const char *start, int len)
{
        int cidx; /* child node index */
        int ccount; /* child node count */
        int ridx = -1; /* index of match or -1 */

        if (pnodes[parent].label.children != 0) {
                /* there are child nodes present to scan */

                cidx = pnodes[parent + 1].child.index;

                for (ccount = pnodes[parent + 1].child.count;
                     ccount > 0;
                     ccount--) {
                        if (pnodes[cidx].label.idx == STAB_WILDCARD) {
                                /* wildcard match */
                                ridx = cidx;
                        } else {
                                if ((pnodes[cidx].label.len == len) &&
                                    (huffcasecmp(pnodes[cidx].label.idx,
                                                 start,
                                                 len) == 0)) {
                                        /* label match */
                                        if ((pnodes[cidx].label.children != 0) &&
                                            (pnodes[cidx + 1].child.count == 1) &&
                                            (pnodes[pnodes[cidx + 1].child.index].label.idx == STAB_EXCEPTION)) {
                                                /* exception to previous */
                                                ridx = -1;
                                        } else {
                                                ridx = cidx;
                                        }
                                        break;
                                }
                        }

                        /* move index to next sibling */
                        if (pnodes[cidx].label.children != 0) {
                                cidx += 2;
                        } else {
                                cidx += 1;
                        }
                }
        }
        return ridx;
}

/*
 * Exported public API
 */
const char *nspsl_getpublicsuffix(const char *hostname)
{
        int treeidx = 0; /* index to current tree node */
        const char *elem_start;
        const char *elem_end;
        int lab_count = 0;

        /* deal with obviously bad hostname */
        if ((hostname == NULL) ||
            (hostname[0]) == 0 ||
            (hostname[0] == DOMSEP)) {
                return NULL;
        }

        /* hostnames are ass backwards and we need to consider elemets
         * from the end first.
         */
        elem_end = hostname + strlen(hostname);
        /* fqdn have a separator on the end */
        if (elem_end[-1] == DOMSEP) {
                elem_end--;
        }
        elem_start = elem_end;

        /* extract the element and check for a match in our tree */
        for(;;) {
                /* find the start of the element */
                while ((elem_start > hostname) && (*elem_start != DOMSEP)) {
                        elem_start--;
                }
                if (*elem_start == DOMSEP) {
                        elem_start++;
                }

                lab_count++;

                /* search child nodes for label */
                treeidx = matchlabel(treeidx, elem_start, elem_end - elem_start);
                if (treeidx == -1) {
                        break;
                }

                if (elem_start == hostname) {
                        /* not valid */
                        return NULL;
                }

                elem_end = elem_start - 1;
                elem_start = elem_end - 1;
        }

        /* The public suffix algorithm says: "the domain must match
         * the public suffix plus one additional label." This
         * requires there to be at least two labels so we need to
         * check
         */
        if (lab_count == 1) {
                if (elem_start == hostname) {
                        elem_start = NULL;
                } else {
                        /* strip the non matching part */
                        elem_start -= 2;
                        while (elem_start > hostname && *elem_start != DOMSEP) {
                                elem_start--;
                        }
                        if (*elem_start == DOMSEP)
                                elem_start++;
                }
        }

        return elem_start;
}
