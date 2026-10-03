#!/usr/bin/env ruby
# frozen_string_literal: true
#
# End-to-end smoke test for the Ruby SDK.
#
# Creates a vault, verifies its basic properties, and removes the file.
# Run from the repository root with:
#
#     LD_LIBRARY_PATH=target/debug ruby bindings/ruby/examples/smoke/smoke.rb

require 'rubygems'
require 'fileutils'
require 'tmpdir'

$LOAD_PATH.unshift(File.expand_path('../../', __dir__))
require 'nexusq'

def assert(condition, message)
  raise "ASSERTION FAILED: #{message}" unless condition
  puts "ok - #{message}"
end

Dir.mktmpdir('nexusq-ruby-smoke-') do |dir|
  vault_path = File.join(dir, 'test.nqv')
  password = 'correct horse battery staple'

  vault = Nexusq::Vault.new_from_path(vault_path, password, 'smoke-test')

  assert(File.exist?(vault_path), 'vault file exists on disk')
  assert(vault.path == vault_path, 'vault.path matches input path')
  assert(vault.format_version == 1, 'format_version is 1')

  puts 'smoke test passed'
end
