# frozen_string_literal: true

# Smoke test for the NEXUS-Q Ruby SDK.
#
# Run from the repository root:
#   NEXUSQ_LIBRARY=target/debug/libnexusq.so ruby bindings/ruby/examples/smoke/smoke.rb

require "rubygems"
require "tmpdir"
require_relative "../../nexusq"

puts "nexusq version: #{Nexusq.version}"

path = File.join(Dir.tmpdir, "nexusq_ruby_smoke_#{$$}.nqv")
File.delete(path) if File.exist?(path)

begin
  vault = Nexusq::Vault.create(path, "ruby-test", "ruby-smoke")

  abort "vault file was not created" unless File.file?(path)
  abort "vault.path does not match input" unless vault.path == path
  abort "format_version must be 1" unless vault.format_version == 1

  puts "vault created at #{vault.path}"
  puts "vault format version: #{vault.format_version}"
  puts "smoke test passed"
ensure
  File.delete(path) if File.exist?(path)
end
