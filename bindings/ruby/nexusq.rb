# frozen_string_literal: true

# NEXUS-Q Ruby bindings.
#
# This is a thin FFI wrapper over the C SDK. It does not reimplement
# cryptography or business logic; every operation delegates to libnexusq.

require "ffi"

module Nexusq
  extend FFI::Library

  ffi_lib ENV.fetch("NEXUSQ_LIBRARY", "nexusq")

  attach_function :nexusq_version, [], :string
  attach_function :nexusq_last_error_message, [], :string
  attach_function :nexusq_vault_create, [:string, :string, :string], :int32
  attach_function :nexusq_vault_format_version, [:string], :int32

  def self.version
    nexusq_version
  end

  def self.last_error
    nexusq_last_error_message
  end

  class Vault
    attr_reader :path, :format_version

    def self.create(path, password, label = nil)
      rc = Nexusq.nexusq_vault_create(path, password, label)
      raise Error, Nexusq.last_error || "NEXUS-Q operation failed" unless rc.zero?

      version = Nexusq.nexusq_vault_format_version(path)
      raise Error, Nexusq.last_error || "NEXUS-Q operation failed" if version.negative?

      new(path, version)
    end

    def initialize(path, format_version)
      @path = path
      @format_version = format_version
    end
    private_class_method :new
  end

  class Error < StandardError
  end
end
