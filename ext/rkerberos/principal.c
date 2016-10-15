#include <rkerberos.h>

VALUE cKrb5Principal;

void rkrb5_princ_mark(RUBY_KRB5_PRINC* ptr){
  rb_gc_mark(ptr->context);
}

VALUE rkrb5_princ_close(VALUE self){
  RUBY_KRB5_PRINC* ptr;

  Data_Get_Struct(self, RUBY_KRB5_PRINC, ptr);

  if(ptr->ctx && ptr->principal){
    krb5_free_principal(ptr->ctx, ptr->principal);
  }

  ptr->ctx = NULL;

  return Qtrue;
}
// Free function for the Kerberos::Krb5::Keytab class.
static void rkrb5_princ_free(RUBY_KRB5_PRINC* ptr){
  if(!ptr)
    return;

  if(ptr->ctx && ptr->principal){
    krb5_free_principal(ptr->ctx, ptr->principal);
  }

  free(ptr);
}

// Allocation function for the Kerberos::Krb5::Keytab class.
static VALUE rkrb5_princ_allocate(VALUE klass){
  RUBY_KRB5_PRINC* ptr = malloc(sizeof(RUBY_KRB5_PRINC));
  memset(ptr, 0, sizeof(RUBY_KRB5_PRINC));
  return Data_Wrap_Struct(klass, rkrb5_princ_mark, rkrb5_princ_free, ptr);
}

/*
 * call-seq:
 *   Kerberos::Krb5::Principal.new(name)
 *
 * Creates and returns a new Krb5::Principal object. If a block is provided
 * then it yields itself.
 *
 * Example:
 *
 *   principal1 = Kerberos::Krb5::Principal.new('Jon')
 *
 *   principal2 = Kerberos::Krb5::Principal.new('Jon') do |pr|
 *     pr.expire_time = Time.now + 20000
 *   end
 */
static VALUE rkrb5_princ_initialize(int argc, VALUE* argv, VALUE self){
  RUBY_KRB5_PRINC* ptr;
  RUBY_KRB5_CONTEXT* ctxptr;
  krb5_error_code kerror;
  VALUE v_name, v_context;
  char* name;

  Data_Get_Struct(self, RUBY_KRB5_PRINC, ptr); 
  rb_scan_args(argc, argv, "11", &v_name, &v_context);

  if(NIL_P(v_context)){
    v_context = rb_class_new_instance(0, NULL, cKrb5Context);
  }
  else{
    if(CLASS_OF(v_context) != cKrb5Context){
      rb_raise(rb_eTypeError, "wrong argument type %s (expected Kerberos::Krb5::Context)",
        rb_obj_classname(v_context));
    }
  }

  Data_Get_Struct(v_context, RUBY_KRB5_CONTEXT, ctxptr);
  ptr->ctx = ctxptr->ctx;
  ptr->context = v_context;

  Check_Type(v_name, T_STRING);
  name = StringValueCStr(v_name);
  kerror = krb5_parse_name(ptr->ctx, name, &ptr->principal);

  if(kerror){
    rb_raise(cKrb5Exception, "krb5_parse_name failed: %s", error_message(kerror));
  }

  rb_iv_set(self, "@principal", v_name);

  rb_iv_set(self, "@attributes", Qnil);
  rb_iv_set(self, "@aux_attributes", Qnil);
  rb_iv_set(self, "@expire_time", Qnil);
  rb_iv_set(self, "@fail_auth_count", Qnil);
  rb_iv_set(self, "@last_failed", Qnil);
  rb_iv_set(self, "@last_password_change", Qnil);
  rb_iv_set(self, "@last_success", Qnil);
  rb_iv_set(self, "@max_life", Qnil); 
  rb_iv_set(self, "@max_renewable_life", Qnil); 
  rb_iv_set(self, "@mod_date", Qnil);
  rb_iv_set(self, "@mod_name", Qnil);
  rb_iv_set(self, "@password_expiration", Qnil);
  rb_iv_set(self, "@policy", Qnil);
  rb_iv_set(self, "@kvno", Qnil);

  if(rb_block_given_p()){
    rb_ensure(rb_yield, self, rkrb5_princ_close, self);
    return Qnil;
  }

  return self;
}

/*
 * call-seq:
 *   principal.realm
 *
 * Returns the realm for the given principal.
 */
static VALUE rkrb5_princ_get_realm(VALUE self){
  RUBY_KRB5_PRINC* ptr;
  Data_Get_Struct(self, RUBY_KRB5_PRINC, ptr); 

  if(!ptr->ctx){
    rb_raise(cKrb5Exception, "no context has been established");
  }

  return rb_str_new2(krb5_princ_realm(ptr->ctx, ptr->principal)->data);
}

/*
 * call-seq:
 *   principal.realm = 'YOUR.REALM'
 *
 * Sets the realm for the given principal.
 */
static VALUE rkrb5_princ_set_realm(VALUE self, VALUE v_realm){
  RUBY_KRB5_PRINC* ptr;

  Data_Get_Struct(self, RUBY_KRB5_PRINC, ptr); 

  Check_Type(v_realm, T_STRING);

  if(!ptr->ctx){
    rb_raise(cKrb5Exception, "no context has been established");
  }

  krb5_set_principal_realm(ptr->ctx, ptr->principal, StringValueCStr(v_realm));

  return v_realm;
}

/*
 * call-seq:
 *   principal1 == principal2
 *
 * Returns whether or not two principals are the same.
 */
static VALUE rkrb5_princ_equal(VALUE self, VALUE v_other){
  RUBY_KRB5_PRINC* ptr1;
  RUBY_KRB5_PRINC* ptr2;
  VALUE v_bool = Qfalse;

  Data_Get_Struct(self, RUBY_KRB5_PRINC, ptr1); 
  Data_Get_Struct(v_other, RUBY_KRB5_PRINC, ptr2); 

  if(!ptr1->ctx || !ptr2->ctx){
    rb_raise(cKrb5Exception, "no context has been established");
  }

  if(krb5_principal_compare(ptr1->ctx, ptr1->principal, ptr2->principal))
    v_bool = Qtrue;

  return v_bool;
}

/* 
 * call-seq:
 *   principal.inspect
 *
 * A custom inspect method for the Principal object.
 */
static VALUE rkrb5_princ_inspect(VALUE self){
  VALUE v_str;
  RUBY_KRB5_PRINC* ptr;

  Data_Get_Struct(self, RUBY_KRB5_PRINC, ptr);

  if(!ptr->ctx){
    rb_raise(cKrb5Exception, "no context has been established");
  }

  v_str = rb_str_new2("#<");
  rb_str_buf_cat2(v_str, rb_obj_classname(self));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "attributes=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@attributes")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "aux_attributes=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@aux_attributes")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "expire_time=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@expire_time")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "fail_auth_count=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@fail_auth_count")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "kvno=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@kvno")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "last_failed=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@last_failed")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "last_password_change=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@last_password_change")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "last_success=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@last_success")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "max_life=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@max_life")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "max_renewable_life=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@max_renewable_life")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "mod_date=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@mod_date")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "mod_name=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@mod_name")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "password_expiration=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@password_expiration")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "policy=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@policy")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, "principal=");
  rb_str_buf_append(v_str, rb_inspect(rb_iv_get(self, "@principal")));
  rb_str_buf_cat2(v_str, " ");

  rb_str_buf_cat2(v_str, ">");

  return v_str;
}

VALUE rkrb5_princ_get_context(VALUE self){
  RUBY_KRB5_PRINC* ptr;

  Data_Get_Struct(self, RUBY_KRB5_PRINC, ptr);

  if(!ptr->ctx){
    rb_raise(cKrb5Exception, "no context has been established");
  }
  return ptr->context;
}

void Init_principal(){
  /* The Kerberos::Krb5::Principal class encapsulates a Kerberos principal. */
  cKrb5Principal = rb_define_class_under(cKrb5, "Principal", rb_cObject);

  // Allocation Function

  rb_define_alloc_func(cKrb5Principal, rkrb5_princ_allocate);

  // Constructor

  rb_define_method(cKrb5Principal, "initialize", rkrb5_princ_initialize, -1);

  // Instance Methods

  rb_define_method(cKrb5Principal, "inspect", rkrb5_princ_inspect, 0);
  rb_define_method(cKrb5Principal, "realm", rkrb5_princ_get_realm, 0);
  rb_define_method(cKrb5Principal, "realm=", rkrb5_princ_set_realm, 1);
  rb_define_method(cKrb5Principal, "==", rkrb5_princ_equal, 1);
  rb_define_method(cKrb5Principal, "context", rkrb5_princ_get_context, 0);
  rb_define_method(cKrb5Principal, "close", rkrb5_princ_close, 0);

  // Attributes

  rb_define_attr(cKrb5Principal, "attributes", 1, 1);
  rb_define_attr(cKrb5Principal, "aux_attributes", 1, 1);
  rb_define_attr(cKrb5Principal, "expire_time", 1, 1);
  rb_define_attr(cKrb5Principal, "fail_auth_count", 1, 1);
  rb_define_attr(cKrb5Principal, "kvno", 1, 1);
  rb_define_attr(cKrb5Principal, "last_failed", 1, 1);
  rb_define_attr(cKrb5Principal, "last_password_change", 1, 1);
  rb_define_attr(cKrb5Principal, "last_success", 1, 1);
  rb_define_attr(cKrb5Principal, "max_life", 1, 1);
  rb_define_attr(cKrb5Principal, "max_renewable_life", 1, 1);
  rb_define_attr(cKrb5Principal, "mod_date", 1, 1);
  rb_define_attr(cKrb5Principal, "mod_name", 1, 1);
  rb_define_attr(cKrb5Principal, "password_expiration", 1, 1);
  rb_define_attr(cKrb5Principal, "policy", 1, 1);
  rb_define_attr(cKrb5Principal, "principal", 1, 0);

  // Aliases

  rb_define_alias(cKrb5Principal, "name", "principal");
}
