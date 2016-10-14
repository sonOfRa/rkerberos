########################################################################
# test_context.rb
#
# Test suite for the Kerberos::Krb5::Context class.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'open3'
require 'test/unit'
require 'rkerberos'

class TC_Krb5_Context < Test::Unit::TestCase
  def setup
    @context = Kerberos::Krb5::Context.new
  end

  test "close basic functionality" do
    assert_respond_to(@context, :close)
    assert_nothing_raised{ @context.close }
  end

  test "calling close multiple times is harmless" do
    assert_nothing_raised{ @context.close }
    assert_nothing_raised{ @context.close }
    assert_nothing_raised{ @context.close }
  end

  test "constructor accepts an optional 'secure' argument" do
    assert_nothing_raised { Kerberos::Krb5::Context.new }
    assert_nothing_raised { Kerberos::Krb5::Context.new(true) }
  end

  test "constructor accepts zero or one arguments" do
    assert_raise(ArgumentError) { Kerberos::Krb5::Context.new(true, 1) }
  end

  test "secure attribute is true when passing 'true' to the constructor" do
    assert_true(Kerberos::Krb5::Context.new(true).secure)
  end

  test "secure attribute is false when passing 'false', 'nil' or nothing to the constructor" do
    assert_false(Kerberos::Krb5::Context.new(false).secure)
    assert_false(Kerberos::Krb5::Context.new(nil).secure)
    assert_false(Kerberos::Krb5::Context.new.secure)
  end

  def teardown
    @context.close
    @context = nil
  end
end
