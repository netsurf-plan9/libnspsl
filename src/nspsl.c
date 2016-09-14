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

static int matchlabel(int parent, const char *start, int len)
{
	int clast = pnodes[parent].child_index + pnodes[parent].child_count;
	int cidx; /*child node index */
	int ridx = -1; /* index of match or -1 */

	if (pnodes[parent].child_count != 0) {
		/* there are child nodes present to scan */

		for (cidx = pnodes[parent].child_index; cidx < clast; cidx++) {
			if (pnodes[cidx].label == STAB_WILDCARD) {
				/* wildcard match */
				ridx = cidx;
			} else {
				if ((pnodes[cidx].label_len == len) &&
				    (strncasecmp(&stab[pnodes[cidx].label],
						 start,
						 len) == 0)) {

					if ((pnodes[cidx].child_count == 1) &&
					    (pnodes[pnodes[cidx].child_index].label == STAB_EXCEPTION)) {
						/* exception to previous */
						ridx = -1;
					} else {
						ridx = cidx;
					}
					break;
				}
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
