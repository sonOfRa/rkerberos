#include <creds.h>

// Create an instance of this class with the specified credentials
static VALUE rkrb5_creds_create(krb5_creds *increds){
  RUBY_KRB5_CREDS *ptr;
  krb5_error_code kerror;

  ptr = calloc(1, sizeof(RUBY_KRB5_CREDS));
  ptr->creds = calloc(1, sizeof(krb5_creds));
  kerror = krb5_init_context(&ptr->ctx);

  if(kerror){
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));
  }
  kerror = krb5_copy_creds(ptr->ctx, increds, &ptr->creds);
  return Data_Wrap_Struct(cKrb5Creds, 0, rkrb5_creds_free, ptr);
}

static void rkrb5_creds_free(RUBY_KRB5_CREDS *ptr){
  if(!ptr){
    return;
  }

  if(ptr->creds){
    krb5_free_creds(ptr->ctx, ptr->creds);
  }

  if(ptr->ctx){
    krb5_free_context(ptr->ctx);
  }

  free(ptr);
}

void Init_Creds(){
  cKrb5Creds = rb_define_class_under(cKrb5, "Creds", rb_cObject);
}