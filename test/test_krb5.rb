########################################################################
# test_krb5.rb
#
# Test suite for the Kerberos::Krb5 class. At the moment, this suite
# requires that you export "testuser1" to a local keytab file called
# "test.keytab" in the "test" directory for certain tests to pass.
#
# Some tests also require that you have an entry in your .dbrc file for
# 'local-kerberos' with includes a valid principal and password and
# optional $KRB5_CONFIG file, as well as an 'invalid-user-kerberos' entry
# with an invalid user and an 'invalid-pass-kerberos' entry with a valid
# user but an invalid password. The respective tests are skipped if the
# entries are not found.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'open3'
require 'test/unit'
require 'rkerberos'
require 'dbi/dbrc'

class TC_Krb5 < Test::Unit::TestCase
  def self.startup
    @@cache_found = true

    Open3.popen3('klist') do |stdin, stdout, stderr|
      @@cache_found = false unless stderr.gets.nil?
    end

    begin
      @@info = DBI::DBRC.new('local-kerberos')
    rescue DBI::DBRC::Error
      @@info = nil
    end

    begin
      @@invalid_user = DBI::DBRC.new('invalid-user-kerberos')
    rescue DBI::DBRC::Error
      @@invalid_user = nil
    end

    begin
      @@invalid_pass = DBI::DBRC.new('invalid-pass-kerberos')
    rescue DBI::DBRC::Error
      @@invalid_pass = nil
    end

    if @@info
      @@krb5_conf = @@info.driver || ENV['KRB5_CONFIG'] || '/etc/krb5.conf'
    else
      @@krb5_conf = ENV['KRB5_CONFIG'] || '/etc/krb5.conf'
    end
    @@realm = IO.read(@@krb5_conf).split("\n").grep(/default_realm/).first.split('=').last.lstrip.chomp
  end

  def setup
    @krb5    = Kerberos::Krb5.new
    @keytab  = Kerberos::Krb5::Keytab.new.default_name.split(':').last
    @user    = "testuser1@" + @@realm
    @service = "kadmin/admin"
    @realuser = @@info ? @@info.user : nil
    @realpass = @@info ? @@info.password : nil
    @invalid_user_user = @@invalid_user ? @@invalid_user.user : nil
    @invalid_user_pass = @@invalid_user ? @@invalid_user.password : nil
    @invalid_pass_user = @@invalid_pass ? @@invalid_pass.user : nil
    @invalid_pass_pass = @@invalid_pass ? @@invalid_pass.password : nil
  end

  test "version constant" do
    assert_equal('0.1.0', Kerberos::Krb5::VERSION)
  end

  test "constructor accepts a block and yields itself" do
    assert_nothing_raised{ Kerberos::Krb5.new{} }
    Kerberos::Krb5.new{ |krb5| assert_kind_of(Kerberos::Krb5, krb5) }
  end

  test "get_default_realm basic functionality" do
    assert_respond_to(@krb5, :get_default_realm)
    assert_nothing_raised{ @krb5.get_default_realm }
    assert_kind_of(String, @krb5.get_default_realm)
  end

  test "get_default_realm takes no arguments" do
    assert_raise(ArgumentError){ @krb5.get_default_realm('localhost') }
  end

  test "get_default_realm matches what we found in the krb5.conf file" do
    assert_equal(@@realm, @krb5.get_default_realm)
  end

  test "default_realm is an alias for get_default_realm" do
    assert_alias_method(@krb5, :default_realm, :get_default_realm)
  end

  test "set_default_realm basic functionality" do
    assert_respond_to(@krb5, :set_default_realm)
  end

  test "set_default_realm with no arguments uses the default realm" do
    assert_nothing_raised{ @krb5.set_default_realm }
    assert_equal(@@realm, @krb5.get_default_realm)
  end

  test "set_default_realm with an argument sets the default realm as expected" do
    assert_nothing_raised{ @krb5.set_default_realm('TEST.REALM') }
    assert_equal('TEST.REALM', @krb5.get_default_realm)
  end

  test "argument to set_default_realm must be a string" do
    assert_raise(TypeError){ @krb5.set_default_realm(1) }
  end

  test "set_default_realm accepts a maximum of one argument" do
    assert_raise(ArgumentError){ @krb5.set_default_realm('FOO', 'BAR') }
  end

  test "get_init_creds_password basic functionality" do
    assert_respond_to(@krb5, :get_init_creds_password)
  end

  test "get_init_creds_password requires two, three or four arguments" do
    assert_raise(ArgumentError){ @krb5.get_init_creds_password }
    assert_raise(ArgumentError){ @krb5.get_init_creds_password('test') }
    assert_raise(ArgumentError){ @krb5.get_init_creds_password('test', 'foo', 'bar', 'baz', 'quux') }
  end

  test "get_init_creds_password requires string arguments" do
    assert_raise(TypeError){ @krb5.get_init_creds_password(1, 2) }
    assert_raise(TypeError){ @krb5.get_init_creds_password('test', 1) }
    assert_raise(TypeError){ @krb5.get_init_creds_password('test', 'foo', 1) }
  end

  test "calling get_init_creds_password with a real user and password returns true" do
    omit_unless(@@info, "No information for 'local-kerberos' in .dbrc, skipping")
    assert_true(@krb5.get_init_creds_password(@realuser, @realpass))
  end

  test "calling get_init_creds_password with a real user and password and getcreds returns a creds object" do
    omit_unless(@@info, "No information for 'local-kerberos' in .dbrc, skipping")
    assert_instance_of(Kerberos::Krb5::Creds, @krb5.get_init_creds_password(@realuser, @realpass, nil, true))
  end

  test "calling get_init_creds_password with an invalid user raises an error" do
    omit_unless(@@invalid_user, "No information for 'invalid-user-kerberos' in .dbrc, skipping")
    assert_raise(Kerberos::Krb5::Exception){ @krb5.get_init_creds_password(@invalid_user_user, @invalid_user_pass) }
  end

  test "calling get_init_creds_password with an invalid password raises an error" do
    omit_unless(@@invalid_pass, "No information for 'invalid-pass-kerberos' in .dbrc, skipping")
    assert_raise(Kerberos::Krb5::Exception){ @krb5.get_init_creds_password(@invalid_pass_user, @invalid_pass_pass) }
  end

  test "calling get_init_creds_password after closing the object raises an error" do
    @krb5.close
    assert_raise(Kerberos::Krb5::Exception){ @krb5.get_init_creds_password('foo', 'xxx') }
  end

  test "calling get_init_creds_password after closing the object raises a specific error message" do
    @krb5.close
    assert_raise_message('no context has been established'){ @krb5.get_init_creds_password('foo', 'xxx') }
  end

  test "get_init_creds_keytab basic functionality" do
    assert_respond_to(@krb5, :get_init_creds_keytab)
  end

  test "get_init_creds_keytab uses a default keytab if no keytab file is specified" do
    omit_unless(File.exist?(@keytab), "keytab file not found, skipping")
    assert_nothing_raised{ @krb5.get_init_creds_keytab(@user) }
  end

  test "get_init_creds_keytab accepts a keytab" do
    omit_unless(File.exist?(@keytab), "keytab file not found, skipping")
    assert_nothing_raised{ @krb5.get_init_creds_keytab(@user, @keytab) }
  end

  # This test will probably fail (since it defaults to "host") so I've commented it out for now.
  #test "get_init_creds_keytab uses default service principal if no arguments are provided" do
  #  omit_unless(File.exist?(@keytab), "keytab file not found, skipping")
  #  assert_nothing_raised{ @krb5.get_init_creds_keytab }
  #end

  test "get_init_creds_keytab accepts a service name" do
    omit_unless(File.exist?(@keytab), "keytab file not found, skipping")
    assert_nothing_raised{ @krb5.get_init_creds_keytab(@user, @keytab, @service) }
  end

  test "get_init_creds_keytab accepts a credential cache" do
    omit_unless(File.exist?(@keytab), "keytab file not found, skipping")
    assert_nothing_raised{ @krb5.get_init_creds_keytab(@user, @keytab, @service, @ccache) }
  end

  test "get_init_creds_keytab stores credentials in the credential cache" do
    omit_unless(File.exist?(@keytab), "keytab file not found, skipping")
    ccache = Kerberos::Krb5::CredentialsCache.new
    assert_nothing_raised{ @krb5.get_init_creds_keytab(@user, @keytab, @service, @ccache) }
    assert_equal @user, ccache.primary_principal
  end

  test "get_init_creds_keytab requires string arguments" do
    assert_raise(TypeError){ @krb5.get_init_creds_keytab(1) }
    assert_raise(TypeError){ @krb5.get_init_creds_keytab(@user, 1) }
    assert_raise(TypeError){ @krb5.get_init_creds_keytab(@user, @keytab, 1) }
  end

  test "calling get_init_creds_keytab after closing the object raises an error" do
    @krb5.close
    assert_raise(Kerberos::Krb5::Exception){ @krb5.get_init_creds_keytab(@user, @keytab) }
  end

  test "change_password basic functionality" do
    assert_respond_to(@krb5, :change_password)
  end

  test "change_password requires two arguments" do
    assert_raise(ArgumentError){ @krb5.change_password }
    assert_raise(ArgumentError){ @krb5.change_password('XXXXXXXX') }
  end

  test "change_password requires two strings" do
    assert_raise(TypeError){ @krb5.change_password(1, 'XXXXXXXX') }
    assert_raise(TypeError){ @krb5.change_password('XXXXXXXX', 1) }
  end

  test "change_password fails if there is no context or principal" do
    assert_raise(Kerberos::Krb5::Exception){ @krb5.change_password("XXX", "YYY") }
    assert_raise_message('no principal has been established'){ @krb5.change_password("XXX", "YYY") }
  end

  test "get_default_principal basic functionality" do
    assert_respond_to(@krb5, :get_default_principal)
  end

  test "get_default_principal returns a string if cache found" do
    omit_unless(@@cache_found, "No credentials cache found, skipping")
    assert_nothing_raised{ @krb5.get_default_principal }
    assert_kind_of(String, @krb5.get_default_principal)
  end

  test "get_default_principal raises an error if no cache is found" do
    omit_if(@@cache_found, "Credential cache found, skipping")
    assert_raise(Kerberos::Krb5::Exception){ @krb5.get_default_principal }
  end

  test "get_permitted_enctypes basic functionality" do
    assert_respond_to(@krb5, :get_permitted_enctypes)
    assert_nothing_raised{ @krb5.get_permitted_enctypes }
    assert_kind_of(Hash, @krb5.get_permitted_enctypes)
  end

  test "get_permitted_enctypes returns expected results" do
    hash = @krb5.get_permitted_enctypes
    assert_kind_of(Fixnum, hash.keys.first)
    assert_kind_of(String, hash.values.first)
    assert_true(hash.values.first.size > 0)
  end

  def teardown
    @krb5.close
    @krb5 = nil
  end

  def self.shutdown
    @@cache_found = nil
  end
end
