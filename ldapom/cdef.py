from cffi import FFI

ffi = FFI()

ffi.cdef("""
// Type definitions
typedef ... LDAP;
typedef ... LDAPMessage;
typedef ... LDAPControl;
typedef ... BerElement;
typedef ... berval;

typedef struct ldapmod {
    int mod_op;
    char *mod_type;
    union {
        char **modv_strvals;
    //    struct berval **modv_bvals;
    } mod_vals;
} LDAPMod;

#define LDAP_VERSION3 ...
#define LDAP_OPT_PROTOCOL_VERSION ...
#define LDAP_OPT_X_TLS_REQUIRE_CERT ...
#define LDAP_OPT_X_TLS_CACERTFILE ...
#define LDAP_OPT_X_TLS_NEWCTX ...
#define LDAP_OPT_X_TLS_NEVER ...
#define LDAP_OPT_TIMELIMIT ...
#define LDAP_NO_LIMIT ...
#define LDAP_MOD_ADD ...
#define LDAP_MOD_DELETE ...
#define LDAP_MOD_REPLACE ...
#define LDAP_SCOPE_BASE ...
#define LDAP_SCOPE_ONELEVEL ...
#define LDAP_SCOPE_SUBTREE ...
#define LDAP_SUCCESS ...
#define LDAP_NO_SUCH_OBJECT ...
#define LDAP_INVALID_CREDENTIALS ...
#define LDAP_SERVER_DOWN ...

// Function declarations
int ldap_initialize(LDAP **ldp, char *uri);
int ldap_set_option(LDAP *ld, int option, const void *invalue);
int ldap_simple_bind_s(LDAP *ld, const char *who, const char *passwd);
int ldap_search_ext_s(
       LDAP *ld,
       char *base,
       int scope,
       char *filter,
       char *attrs[],
       int attrsonly,
       LDAPControl **serverctrls,
       LDAPControl **clientctrls,
       struct timeval *timeout,
       int sizelimit,
       LDAPMessage **res);

// From ldap_next_entry(3)
int ldap_count_entries( LDAP *ld, LDAPMessage *result );
LDAPMessage *ldap_first_entry( LDAP *ld, LDAPMessage *result );
LDAPMessage *ldap_next_entry( LDAP *ld, LDAPMessage *entry );

// From ldap_get_values(3)
char **ldap_get_values(LDAP *ld, LDAPMessage *entry, char *attr);
int ldap_count_values(char **vals);

// From ldap_get_dn(3)
char *ldap_get_dn( LDAP *ld, LDAPMessage *entry );

// From ldap_first_attribute(3)
char *ldap_first_attribute( LDAP *ld, LDAPMessage *entry, BerElement **berptr );
char *ldap_next_attribute( LDAP *ld, LDAPMessage *entry, BerElement *ber );

// From ldap_add_ext(3)
int ldap_add_ext_s(
       LDAP *ld,
       const char *dn,
       LDAPMod **attrs,
       LDAPControl **sctrls,
       LDAPControl **cctrls );

// From ldap_modify_ext(3)
int ldap_modify_ext_s(
              LDAP *ld,
              char *dn,
              LDAPMod *mods[],
              LDAPControl **sctrls,
              LDAPControl **cctrls );

// From ldap_delete_s(3)
int ldap_delete_s(LDAP *ld, char *dn);

// From ldap_rename_s(3)
int ldap_rename_s(
        LDAP *ld,
        const char *dn,
        const char *newrdn,
        const char *newparent,
        int deleteoldrdn,
        LDAPControl *sctrls[],
        LDAPControl *cctrls[]);

// From ldap_err2string(3)
char *ldap_err2string( int err );

// From ldap_msgfree(3)
int ldap_msgfree( LDAPMessage *msg );

int ldap_passwd_s(
        LDAP *ld,
        struct berval        *user,
        struct berval        *oldpw,
        struct berval        *newpw,
        struct berval *newpasswd,
        LDAPControl **sctrls,
        LDAPControl **cctrls );

// From lber-types(3)
struct berval *ber_bvstr(const char *str);

""")

libldap = ffi.verify(
"""
// Required for ldap_bind_simple
#define LDAP_DEPRECATED 1

#include <ldap.h>
#include <lber.h>
""", libraries=[str("ldap"), str("lber")])
