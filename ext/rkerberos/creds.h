#ifndef RKRB5_CREDS_H_INCLUDED
#define RKRB5_CREDS_H_INCLUDED
#include <rkerberos.h>

VALUE cKrb5Creds;

void rkrb5_creds_free(RUBY_KRB5_CREDS*);
VALUE rkrb5_creds_create(krb5_creds*);
#endif