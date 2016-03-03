/* rewatt.c - Overlay to rewrite some attribute  */
/* Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by the Dominik Bartkiewicz bart@icm.edu.pl for
 * inclusion in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>
#include <regex.h>

#include "ac/string.h"
#include "ac/socket.h"

#include "lutil.h"
#include "slap.h"
#include "config.h"

#define MAX_MATCHES 1

enum {
	REWATT_ATTRIBUTE=1,
	REWATT_REGEX,
	REWATT_SUB,
	REWATT_ATTRIBUTE_T,
	REWATT_REGEX_T
};


typedef struct rewatt_info_t {
	AttributeDescription	*ra_attribute;
	regex_t			*ra_regex;
	char		*ra_sub;
	AttributeDescription	*ra_attribute_t;
	regex_t			*ra_regex_t;
	struct rewatt_info_t	*ra_next;
} rewatt_info_t;

static int
rewatt_cfgen( ConfigArgs *c )
{
	slap_overinst	*on = (slap_overinst *)c->bi;
	rewatt_info_t	*ci = (rewatt_info_t *)on->on_bi.bi_private ;

        if( ci == NULL ) {
                ci = (rewatt_info_t*)ch_calloc( 1, sizeof(rewatt_info_t) );
		ci -> ra_regex = NULL;
		ci -> ra_regex = NULL;
		ci -> ra_sub = NULL;
		ci -> ra_attribute = NULL;
		ci -> ra_attribute_t = NULL;
		ci -> ra_next = NULL;
		on->on_bi.bi_private= (void *) ci;
		Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen:   on->on_bi.bi_private= %p \n", on->on_bi.bi_private, 0, 0);
        } else {
		for (;ci;ci=ci->ra_next) {
        		if( ci->ra_next == NULL ) {
				if(ci->ra_attribute != NULL && c->type == REWATT_ATTRIBUTE &&  c->op != SLAP_CONFIG_EMIT && c->op !=  LDAP_MOD_DELETE){
                			ci->ra_next = (rewatt_info_t*)ch_calloc( 1, sizeof(rewatt_info_t) );
					ci->ra_next -> ra_regex = NULL;
					ci->ra_next -> ra_regex_t = NULL;
					ci->ra_next -> ra_sub = NULL;
					ci->ra_next -> ra_attribute = NULL;
					ci->ra_next -> ra_attribute_t = NULL;
					ci->ra_next -> ra_next = NULL;
					Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen:   on->on_bi.bi_private= %p \n", on->on_bi.bi_private, 0, 0);
				} else {
					break;
				}
        		}
			
		}

	}

	const char		*text;
	int rc = 1;
	int r = 1;
	int i = 0;
	int len = 0;
	for(i=0;i<c->argc;i++){
		Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen:   c->argv[%d]: %s\n", i, c->argv[i], 0);
	}
	Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen:   c->op: %d\n",  c->op, 0,0);
	if ( c->op == SLAP_CONFIG_EMIT ) {
		ci = on->on_bi.bi_private ;
		struct berval	bv;
		Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen SLAP_CONFIG_EMIT :   c->type: %d\n",  c->type, 0,0);
		switch(c->type) {
		case REWATT_ATTRIBUTE:
			len = snprintf( c->cr_msg, sizeof( c->cr_msg ),
				 "%s", 
				ci->ra_attribute->ad_cname.bv_val );

			bv.bv_val = c->cr_msg;
			Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen REWATT_ATTRIBUTE:   c->cr_msg: %s\n",  c->cr_msg, 0,0);
			bv.bv_len = len;
			value_add_one ( &c->rvalue_vals, &bv );
			rc = 0;
			break;
		case REWATT_REGEX:

			//len = snprintf( c->cr_msg, sizeof( c->cr_msg ), "%s", ci->ra_regexp );
			//bv.bv_val = c->cr_msg;
			//Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen REWATT_REGEXP:   c->cr_msg: %s\n",  c->cr_msg, 0,0);
			//bv.bv_len = len;
			//value_add_one ( &c->rvalue_vals, &bv );
			rc = 0;
			break;
		case REWATT_SUB:
			if ( ci->ra_sub ){
				len = snprintf( c->cr_msg, sizeof( c->cr_msg ),
					"%s",
					ci->ra_sub );

				bv.bv_val = c->cr_msg;
				Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen REWATT_SUB:   c->cr_msg: %s\n",  c->cr_msg, 0,0);
				bv.bv_len = len;
				value_add_one ( &c->rvalue_vals, &bv );
			}
			rc = 0;
			break;
		case REWATT_ATTRIBUTE_T:
			if(ci->ra_attribute_t){
				len = snprintf( c->cr_msg, sizeof( c->cr_msg ),
					 "%s", 
					ci->ra_attribute_t->ad_cname.bv_val );
				bv.bv_val = c->cr_msg;
				Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen REWATT_ATTRIBUTE:   c->cr_msg: %s\n",  c->cr_msg, 0,0);
				bv.bv_len = len;
				value_add_one ( &c->rvalue_vals, &bv );
			}
			rc = 0;
			break;
		case REWATT_REGEX_T:
			rc = 0;
			break;

		default:
			rc = 1;
			break;
		}
		return rc;
	} else if ( c->op == LDAP_MOD_DELETE ) {
	        /* FIXME */
	        return 1;
	}
	Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen:   c->type: %d\n",  c->type, 0,0);
	switch( c->type ) {
	case REWATT_ATTRIBUTE:
		if ( c->argc == 2 ){
			r = slap_str2ad( c->argv[1], &(ci->ra_attribute), &text );
			if ( r != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen:  slap_str2ad: return code = %d\n", r, 0,0);
				rc = 1;
			} else {
				Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen:   ci->ra_attribute->ad_cname.bv_val = %s\n",  ci->ra_attribute->ad_cname.bv_val , 0,0);
				rc = 0;
			}
		}
		break;
	case REWATT_REGEX:
		if ( c->argc == 2 ){
			ci->ra_regex=(regex_t *)SLAP_MALLOC(sizeof(regex_t));
			r = regcomp(ci->ra_regex, c->argv[1], REG_EXTENDED);
			if( r ){
				Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen: Could not compile regex r = %d\n", r , 0,0);
				regfree(ci->ra_regex);
				ci->ra_regex=NULL;
				rc = 1;
			} else {
				Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen:   ci->ra_regex make from #> %s <#'\n",  c->argv[1] , 0,0);
				rc = 0;
			}
		}
		break;
	case REWATT_SUB:
		if ( c->argc == 2 ){
			ci->ra_sub=SLAP_MALLOC((strlen(c->argv[1])+1)* sizeof(char) );
			Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen:   ci->ra_sub=malloc(%lu)\n",  ((strlen(c->argv[1])+1)* sizeof(char) ), 0,0);
			strncpy(ci->ra_sub,c->argv[1],strlen(c->argv[1]));
			ci->ra_sub[strlen(c->argv[1])]='\0';
			Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen:   ci->ra_sub= %s\n",  ci->ra_sub, 0,0);
			rc = 0;
		} else {
			ci->ra_sub=malloc(sizeof(char));
			ci->ra_sub[0]='\0';
			rc = 0;
		}
		break;
	case REWATT_ATTRIBUTE_T:
		if ( c->argc == 2 ){
			r = slap_str2ad( c->argv[1], &(ci->ra_attribute_t), &text );
			if ( r != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen:  slap_str2ad: return code = %d\n", r, 0,0);
				rc = 1;
			} else {
				Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen:   ci->ra_attribute_t->ad_cname.bv_val = %s\n",  ci->ra_attribute_t->ad_cname.bv_val , 0,0);
				rc = 0;
			}
		}
		break;
	case REWATT_REGEX_T:
		if ( c->argc == 2 ){
			ci->ra_regex_t=(regex_t *)SLAP_MALLOC(sizeof(regex_t));
			r = regcomp(ci->ra_regex_t, c->argv[1], REG_EXTENDED);
			if( r ){
				Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen: Could not compile regex r = %d\n", r , 0,0);
				regfree(ci->ra_regex_t);
				ci->ra_regex_t=NULL;
				rc = 1;
			} else {
				Debug( LDAP_DEBUG_TRACE, "rewatt_cfgen:   ci->ra_regex_t make from #> %s <#'\n",  c->argv[1] , 0,0);
				rc = 0;
			}
		}
		break;


	default:		
		return 1;
		break;
	}
	return rc;
}
static int
rewatt_search_response_cb( Operation *op, SlapReply *rs )
{
	slap_callback   *sc;
	rewatt_info_t	*rai;
	Entry		*e = NULL;
	Attribute *a;
	char msgbuf[100];
	int reti;
	int i;

	assert( op && op->o_callback && rs );
	Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb \n", 0, 0,0);
	if ( rs->sr_type != REP_SEARCH || !rs->sr_entry ) {
		slap_freeself_cb( op, rs );
		return ( SLAP_CB_CONTINUE );
	}
	sc = op->o_callback;
	rai = (rewatt_info_t *)sc->sc_private;

	for (rai = (rewatt_info_t *)sc->sc_private;rai;rai=rai->ra_next){
		//Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb: rai = %p \n", rai, 0, 0);
		e = rs->sr_entry;
		for ( a = e->e_attrs; a; a = a->a_next ) {
			if ( a->a_desc == rai->ra_attribute ) {
				Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb: rewatt find: %s\n", a->a_desc->ad_cname.bv_val, 0,0);
				break;
				}
		}

		if ( a == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb: rewatt not find: %s\n", rai->ra_attribute->ad_cname.bv_val, 0,0);
			continue;
		}

		Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb: a->a_desc->ad_cname.bv_val: %s\n", a->a_desc->ad_cname.bv_val, 0,0);

		if ( rai->ra_attribute_t != NULL ){
			for ( a = e->e_attrs; a; a = a->a_next ) {
				if ( a->a_desc == rai->ra_attribute_t ) {
					break;
					}
			}
	
			if ( a == NULL ) {
				Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb: rewatt not find ra_attribute_t : %s\n", rai->ra_attribute_t->ad_cname.bv_val, 0,0);
				continue;
			}
		}
		if ( rai->ra_attribute_t != NULL && rai->ra_regex_t != NULL){
			for ( a = e->e_attrs; a; a = a->a_next ) {
				if ( a->a_desc == rai->ra_attribute_t ) {
						for(i=0;i < a->a_numvals ;i++){
							 reti = regexec(rai->ra_regex_t, a->a_vals[i].bv_val , 0 , NULL , REG_NOTBOL | REG_NOTEOL);
							 if (reti == 0) break;
						}
						if (reti == 0 ) break;
					}
			}
	
			if ( a == NULL ) {
				Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb: ra_regex_t REG_NOMATCH in %s \n",  rai->ra_attribute_t->ad_cname.bv_val , 0,0);
				continue;
			}

		}

		//New function for slapd > 2.4.24
		rs_entry2modifiable( op, rs, (slap_overinst *) op->o_bd->bd_info );
		//rs_ensure_entry_modifiable( op, rs, (slap_overinst *) op->o_bd->bd_info );
		e = rs->sr_entry;

		for ( a = e->e_attrs; a; a = a->a_next ) {
			if ( a->a_desc !=  rai->ra_attribute )
				continue;
			for(i=0;i < a->a_numvals ;i++){


				Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb: old  value  %s\n", a->a_vals[i].bv_val, 0,0 );
				Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb: old nvalue  %s\n", a->a_nvals[i].bv_val, 0,0 );

				int j;
				char * val_tmp=NULL;
				regmatch_t matches[MAX_MATCHES];
				
				/* Execute regular expression */
				reti = regexec(rai->ra_regex, a->a_vals[i].bv_val , MAX_MATCHES , matches , REG_NOTBOL | REG_NOTEOL);

				if( !reti ){
					for (j = 0; j <  MAX_MATCHES; j++) {
						if (matches[j].rm_so == -1) {
						    break;
						}
						if (j == 0 ) {
							val_tmp = realloc(val_tmp , (strlen(rai->ra_sub) - matches[j].rm_eo + matches[j].rm_so +1 + strlen(a->a_vals[i].bv_val) ) * sizeof(char));
							if(matches[j].rm_so > 0)
								strncpy( val_tmp,  a->a_vals[i].bv_val, matches[j].rm_so);
							strcpy( val_tmp + matches[j].rm_so,  rai->ra_sub);
							strcpy( val_tmp + strlen(val_tmp) , a->a_vals[i].bv_val + matches[j].rm_eo );
						}
					}
					Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb: val_tmp value: %s\n", val_tmp, 0, 0 );
					a->a_vals[i].bv_val = realloc( a->a_vals[i].bv_val , ( strlen(val_tmp) + 1 ) * sizeof(char)  );
					a->a_nvals[i].bv_val = realloc( a->a_nvals[i].bv_val , ( strlen(val_tmp) + 1 )  * sizeof(char)  );
					Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb: after SLAP_REALLOC a->a_[n]vals[%d]->bv_val to  %lu\n", i ,(strlen(val_tmp)+1)*sizeof(char), 0 );
					strcpy( a->a_vals[i].bv_val ,val_tmp);
					strcpy( a->a_nvals[i].bv_val ,val_tmp);
					Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb: new a->a_[n]vals[%d].bv_val= %s\n",i, a->a_nvals[i].bv_val, 0 );
					a->a_vals[i].bv_len= strlen(val_tmp) ;
					a->a_nvals[i].bv_len= strlen(val_tmp) ;
					Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb: new a->a_[n]vals[%d].bv_len= %zu\n",i, strlen(val_tmp), 0 );
					if (val_tmp) free(val_tmp);
				}
				else if( reti == REG_NOMATCH ){
					Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb: REG_NOMATCH in : %s\n",  a->a_vals[i].bv_val  , 0,0);
				}
				else{
				        regerror(reti, rai->ra_regex, msgbuf, sizeof(msgbuf));
					Debug( LDAP_DEBUG_TRACE, "rewatt_search_response_cb: Regex match failed: %s\n",  msgbuf , 0,0);
					break;
				}
			}

        	}
	}
	return ( SLAP_CB_CONTINUE );
}

static int
rewatt_search_cleanup_cb( Operation *op, SlapReply *rs )
{
	if ( rs->sr_type == REP_RESULT || rs->sr_err != LDAP_SUCCESS ) {
		slap_freeself_cb( op, rs );
	}

	return SLAP_CB_CONTINUE;
}

static int
rewatt_search( Operation *op, SlapReply *rs )
{
        slap_overinst   *on = (slap_overinst *)op->o_bd->bd_info;
        rewatt_info_t    *ci = (rewatt_info_t *)on->on_bi.bi_private;
	slap_callback	*sc;

	Debug( LDAP_DEBUG_TRACE, "rewatt_search \n", 0, 0, 0 );
	sc = op->o_tmpcalloc( 1, sizeof( *sc ), op->o_tmpmemctx );
	sc->sc_response = rewatt_search_response_cb;
	sc->sc_cleanup = rewatt_search_cleanup_cb;
	sc->sc_next = op->o_callback;
        sc->sc_private = ci;
	op->o_callback = sc;

	return SLAP_CB_CONTINUE;

}
static int
rewatt_db_destroy(
        BackendDB *be,
        ConfigReply *cr )
{
        slap_overinst *on = (slap_overinst *)be->bd_info;

        on->on_bi.bi_private = NULL;

        return 0;
}

static slap_overinst rewatt_ovl;

static ConfigDriver     rewatt_cfgen;

static ConfigTable rewatt_cfg[] = {
	{ "ra_attribute", NULL, 2, 2, 0, ARG_MAGIC|REWATT_ATTRIBUTE,
		rewatt_cfgen, "(OLcfgCtAt:22.1 NAME 'olcRewattAttribute' "
			"DESC 'Attribute Name' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString "
			"X-ORDERED 'VALUES' )", NULL, NULL },
	{ "ra_regex", NULL, 2, 2, 0, ARG_MAGIC|REWATT_REGEX,
		rewatt_cfgen, "(OLcfgCtAt:22.2 NAME 'olcRewattRegex' "
			"DESC 'Regex' "
			"SYNTAX OMsDirectoryString "
			"X-ORDERED 'VALUES' )", NULL, NULL },
	{ "ra_sub", NULL, 1, 2, 0, ARG_MAGIC|REWATT_SUB,
		rewatt_cfgen, "(OLcfgCtAt:22.3 NAME 'olcRewattSub' "
			"DESC 'Substitution' "
			"SYNTAX OMsDirectoryString "
			"X-ORDERED 'VALUES' )", NULL, NULL },
	{ "ra_attribute_t", NULL, 2, 2, 0, ARG_MAGIC|REWATT_ATTRIBUTE_T,
		rewatt_cfgen, "(OLcfgCtAt:22.4 NAME 'olcRewattAttributeT' "
			"DESC 'Triggering Attribute Name' "
			"SYNTAX OMsDirectoryString "
			"X-ORDERED 'VALUES' )", NULL, NULL },
	{ "ra_regex_t", NULL, 2, 2, 0, ARG_MAGIC|REWATT_REGEX_T,
		rewatt_cfgen, "(OLcfgCtAt:22.5 NAME 'olcRewattRegexT' "
			"DESC 'Triggering Regex' "
			"SYNTAX OMsDirectoryString "
			"X-ORDERED 'VALUES' )", NULL, NULL },
	{ NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

static ConfigOCs rewatt_ocs[] = {
	{ "( OLcfgCtOc:22.1 "
	  "NAME 'olcRewattConfig' "
	  "DESC 'Attribute Rewatt configuration' "
	  "SUP olcOverlayConfig "
	  "MUST ( olcRewattAttribute $ olcRewattRegex) " 
	  "MAY ( olcRewattRegexT $ olcRewattSub $ olcRewattAttributeT ) " 
	  " ) ", 
	  Cft_Overlay, rewatt_cfg },
	{ NULL, 0, NULL }
};

static int
rewatt_initialize( void ) {
	int rc;
	rewatt_ovl.on_bi.bi_type = "rewatt";

	rewatt_ovl.on_bi.bi_db_destroy = rewatt_db_destroy;
	rewatt_ovl.on_bi.bi_op_search = rewatt_search;
	rewatt_ovl.on_bi.bi_cf_ocs = rewatt_ocs;
	
	Debug( LDAP_DEBUG_TRACE, "rewatt_initialize: rewatt_ovl.on_bi.bi_type=  %s\n", rewatt_ovl.on_bi.bi_type , 0,0 );
	rc = config_register_schema ( rewatt_cfg,rewatt_ocs );
	if ( rc ) 
		return rc;
	return overlay_register( &rewatt_ovl );
}

int init_module(int argc, char *argv[]) {
	return rewatt_initialize();
}

