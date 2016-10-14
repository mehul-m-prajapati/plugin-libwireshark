#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <epan/epan_dissect.h>

static int print_hidden = 1;

static void
proto_tree_print_node(proto_node *node, gpointer data)
{
    gchar *label_ptr;
    field_info *fi;
    char *s;

    fi = PITEM_FINFO(node);

    if (fi->hfinfo->id == hf_text_only) {
	/* XXX - Text label. Do nothing for now. */

	/* Get the text */
	label_ptr = fi->rep ? fi->rep->representation : "";

	printf("Text label: %s\n", label_ptr);
    } else if (!PROTO_ITEM_IS_HIDDEN(node)
	       || (PROTO_ITEM_IS_HIDDEN(node) && print_hidden) ) {
	/*
	 * Normal protocols and fields
	 */

	switch (fi->hfinfo->type) {
	case FT_PROTOCOL:
	    printf("proto = %s, start = %d, len = %d\n",
		   fi->hfinfo->abbrev, fi->start, fi->length);
	    break;
	case FT_NONE:
	    printf("fi->hfinfo->type is FT_NONE\n");
	    break;
	default:
	    s = fvalue_to_string_repr(&fi->value, FTREPR_DISPLAY, NULL);

	    /*
	     * fi->hfinfo->abbrev has the name of the field. This is what we
	     * want to use for the name of the Tcl variable. I hope these
	     * abbreviations are unique across all Wireshark dissectors.
	     * Otherwise we're in trouble.
	     *
	     * Since the same dissector may be run more than once (for example,
	     * the IP dissector in an ICMP message carrying an error) we need
	     * to think about a way of sending to the Tcl world the same field
	     * name but in different layers.
	     */
	    printf("  %s: %s\n", fi->hfinfo->abbrev, s);

	    g_free(s); /* fvalue_to_string_repr() allocated for us. Needs to
			  be freed. */
	}
    }

    /*
     * What is this assert() in the Wireshark code for, again? I don't
     * know why this condition needs to be satisfied; I just stole the code
     * and this came with the bounty. EP.-
     */
    g_assert(fi->tree_type >= -1 && fi->tree_type < num_tree_types);

    /* We always make all levels available to the Tcl world; recurse here */
    if (node->first_child != NULL)
	proto_tree_children_foreach(node, proto_tree_print_node, data);
}

void
proto_tree_print(epan_dissect_t *edt)
{
    printf("-----------------------------------\n");

    proto_tree_children_foreach(edt->tree, proto_tree_print_node, NULL);
}

static char *
get_line_buf(size_t len)
{
    static char *line_bufp = NULL;
    static size_t line_buf_len = 256;
    size_t new_line_buf_len;

    for (new_line_buf_len = line_buf_len; new_line_buf_len < len;
	 new_line_buf_len *= 2)
	;

    if (line_bufp == NULL) {
	line_buf_len = new_line_buf_len;
	line_bufp = g_malloc(line_buf_len + 1);
    } else {
	if (new_line_buf_len > line_buf_len) {
	    line_buf_len = new_line_buf_len;
	    line_bufp = g_realloc(line_bufp, line_buf_len + 1);
	}
    }

    return line_bufp;
}

void
print_columns(column_info *cinfo)
{
    char *line_bufp;
    int i;
    size_t buf_offset;
    size_t column_len;

    line_bufp = get_line_buf(256);
    buf_offset = 0;
    *line_bufp = '\0';

    for (i = 0; i < cinfo->num_cols; i++) {
	switch (cinfo->col_fmt[i]) {
	case COL_NUMBER:
	    column_len = strlen(cinfo->col_data[i]);
	    if (column_len < 3)
		column_len = 3;
	    line_bufp = get_line_buf(buf_offset + column_len);
	    sprintf(line_bufp + buf_offset, "%3s", cinfo->col_data[i]);
	    break;

	case COL_CLS_TIME:
	case COL_REL_TIME:
	case COL_ABS_TIME:
	case COL_ABS_DATE_TIME: /* XXX - wider */
	    column_len = strlen(cinfo->col_data[i]);
	    if (column_len < 10)
		column_len = 10;
	    line_bufp = get_line_buf(buf_offset + column_len);
	    sprintf(line_bufp + buf_offset, "%10s", cinfo->col_data[i]);
	    break;

	case COL_DEF_SRC:
	case COL_RES_SRC:
	case COL_UNRES_SRC:
	case COL_DEF_DL_SRC:
	case COL_RES_DL_SRC:
	case COL_UNRES_DL_SRC:
	case COL_DEF_NET_SRC:
	case COL_RES_NET_SRC:
	case COL_UNRES_NET_SRC:
	    column_len = strlen(cinfo->col_data[i]);
	    if (column_len < 12)
		column_len = 12;
	    line_bufp = get_line_buf(buf_offset + column_len);
	    sprintf(line_bufp + buf_offset, "%12s", cinfo->col_data[i]);
	    break;

	case COL_DEF_DST:
	case COL_RES_DST:
	case COL_UNRES_DST:
	case COL_DEF_DL_DST:
	case COL_RES_DL_DST:
	case COL_UNRES_DL_DST:
	case COL_DEF_NET_DST:
	case COL_RES_NET_DST:
	case COL_UNRES_NET_DST:
	    column_len = strlen(cinfo->col_data[i]);
	    if (column_len < 12)
		column_len = 12;
	    line_bufp = get_line_buf(buf_offset + column_len);
	    sprintf(line_bufp + buf_offset, "%-12s", cinfo->col_data[i]);
	    break;

	default:
	    column_len = strlen(cinfo->col_data[i]);
	    line_bufp = get_line_buf(buf_offset + column_len);
	    strcat(line_bufp + buf_offset, cinfo->col_data[i]);
	    break;
	}

	buf_offset += column_len;

	if (i != cinfo->num_cols - 1) {
	    /*
	     * This isn't the last column, so we need to print a
	     * separator between this column and the next.
	     *
	     * If we printed a network source and are printing a
	     * network destination of the same type next, separate
	     * them with "->"; if we printed a network destination
	     * and are printing a network source of the same type
	     * next, separate them with "<-"; otherwise separate them
	     * with a space.
	     *
	     * We add enough space to the buffer for " <- " or " -> ",
	     * even if we're only adding " ".
	     */

	    line_bufp = get_line_buf(buf_offset + 4);

	    switch (cinfo->col_fmt[i]) {
	    case COL_DEF_SRC:
	    case COL_RES_SRC:
	    case COL_UNRES_SRC:
		switch (cinfo->col_fmt[i + 1]) {
		case COL_DEF_DST:
		case COL_RES_DST:
		case COL_UNRES_DST:
		    strcat(line_bufp + buf_offset, " -> ");
		    buf_offset += 4;
		    break;
		default:
		    strcat(line_bufp + buf_offset, " ");
		    buf_offset += 1;
		}
		break;

	    case COL_DEF_DL_SRC:
	    case COL_RES_DL_SRC:
	    case COL_UNRES_DL_SRC:
		switch (cinfo->col_fmt[i + 1]) {
		case COL_DEF_DL_DST:
		case COL_RES_DL_DST:
		case COL_UNRES_DL_DST:
		    strcat(line_bufp + buf_offset, " -> ");
		    buf_offset += 4;
		    break;
		default:
		    strcat(line_bufp + buf_offset, " ");
		    buf_offset += 1;
		}
		break;

	    case COL_DEF_NET_SRC:
	    case COL_RES_NET_SRC:
	    case COL_UNRES_NET_SRC:
		switch (cinfo->col_fmt[i + 1]) {
		case COL_DEF_NET_DST:
		case COL_RES_NET_DST:
		case COL_UNRES_NET_DST:
		    strcat(line_bufp + buf_offset, " -> ");
		    buf_offset += 4;
		    break;
		default:
		    strcat(line_bufp + buf_offset, " ");
		    buf_offset += 1;
		}
		break;

	    case COL_DEF_DST:
	    case COL_RES_DST:
	    case COL_UNRES_DST:
		switch (cinfo->col_fmt[i + 1]) {
		case COL_DEF_SRC:
		case COL_RES_SRC:
		case COL_UNRES_SRC:
		    strcat(line_bufp + buf_offset, " <- ");
		    buf_offset += 4;
		    break;
		default:
		    strcat(line_bufp + buf_offset, " ");
		    buf_offset += 1;
		}
		break;

	    case COL_DEF_DL_DST:
	    case COL_RES_DL_DST:
	    case COL_UNRES_DL_DST:
		switch (cinfo->col_fmt[i + 1]) {
		case COL_DEF_DL_SRC:
		case COL_RES_DL_SRC:
		case COL_UNRES_DL_SRC:
		    strcat(line_bufp + buf_offset, " <- ");
		    buf_offset += 4;
		    break;
		default:
		    strcat(line_bufp + buf_offset, " ");
		    buf_offset += 1;
		}
		break;

	    case COL_DEF_NET_DST:
	    case COL_RES_NET_DST:
	    case COL_UNRES_NET_DST:
		switch (cinfo->col_fmt[i + 1]) {
		case COL_DEF_NET_SRC:
		case COL_RES_NET_SRC:
		case COL_UNRES_NET_SRC:
		    strcat(line_bufp + buf_offset, " <- ");
		    buf_offset += 4;
		    break;
		default:
		    strcat(line_bufp + buf_offset, " ");
		    buf_offset += 1;
		}
		break;

	    default:
		strcat(line_bufp + buf_offset, " ");
		buf_offset += 1;
	    }
	}
    }

    puts(line_bufp);
}
