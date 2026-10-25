# frozen_string_literal: true

# NEXUS-Q Ruby bindings.
#
# This is a thin FFI wrapper over the C SDK. It does not reimplement
# cryptography or business logic; every operation delegates to libnexusq.

require "ffi"
require "digest"
require "fileutils"
require "open-uri"
require "rbconfig"

module Nexusq
  extend FFI::Library

  RUNTIME_VERSION = "4.1.2"

  def self.resolve_library
    override = ENV["NEXUSQ_LIBRARY"]
    return override unless override.nil? || override.empty?

    os = RbConfig::CONFIG.fetch("host_os", "").downcase
    arch = RbConfig::CONFIG.fetch("host_cpu", "").downcase
    if os.include?("linux") && ["/lib/ld-musl-x86_64.so.1", "/lib/ld-musl-aarch64.so.1", "/lib/ld-musl-armhf.so.1"].any? { |path| File.exist?(path) }
      raise LoadError, "Prebuilt NEXUS-Q Linux runtimes require glibc, not musl/Alpine; set NEXUSQ_LIBRARY to a compatible build."
    end
    asset, local_name = if os.include?("linux") && %w[x86_64 amd64].include?(arch)
      ["nexusq-sdk-runtime-linux-x64.so", "libnexusq.so"]
    elsif os.include?("linux") && %w[aarch64 arm64].include?(arch)
      ["nexusq-sdk-runtime-linux-arm64.so", "libnexusq.so"]
    elsif os.include?("darwin") && %w[arm64 aarch64].include?(arch)
      ["nexusq-sdk-runtime-macos-arm64.dylib", "libnexusq.dylib"]
    elsif os.match?(/mingw|mswin/) && %w[x86_64 amd64].include?(arch)
      ["nexusq-sdk-runtime-windows-x64.dll", "nexusq.dll"]
    else
      raise LoadError, "No prebuilt NEXUS-Q runtime for #{os}/#{arch}; set NEXUSQ_LIBRARY to a compatible library path."
    end

    cache = File.join(Dir.home, ".cache", "nexusq", RUNTIME_VERSION, asset)
    library = File.join(cache, local_name)
    digest_file = "#{library}.sha256"
    FileUtils.mkdir_p(cache)
    if File.file?(library) && File.file?(digest_file) &&
       Digest::SHA256.file(library).hexdigest == File.read(digest_file).strip
      return library
    end

    base = "https://github.com/lecodev-26/nexus-q/releases/download/v#{RUNTIME_VERSION}/"
    checksums = URI.open("#{base}NATIVE-RUNTIME-SHA256SUMS", "User-Agent" => "NEXUS-Q Ruby SDK", open_timeout: 10, read_timeout: 30, &:read)
    expected = checksums.lines.find { |line| line.strip.end_with?("  #{asset}") }&.split&.first
    raise LoadError, "No published checksum for #{asset}" unless expected

    bytes = URI.open("#{base}#{asset}", "User-Agent" => "NEXUS-Q Ruby SDK", open_timeout: 10, read_timeout: 60, &:read)
    actual = Digest::SHA256.hexdigest(bytes)
    raise LoadError, "SHA-256 mismatch for #{asset}; refusing to load an unverified runtime" unless actual == expected.downcase

    temporary = "#{library}.download"
    File.binwrite(temporary, bytes)
    File.rename(temporary, library)
    File.write(digest_file, "#{actual}\n")
    library
  rescue LoadError
    raise
  rescue StandardError => e
    raise LoadError, "Unable to obtain verified NEXUS-Q #{RUNTIME_VERSION} runtime: #{e.message}. Set NEXUSQ_LIBRARY to a compatible library path."
  end

  ffi_lib resolve_library

  attach_function :nexusq_version, [], :string
  attach_function :nexusq_backend_name, [], :string
  attach_function :nexusq_backend_is_experimental, [], :uint8
  attach_function :nexusq_last_error_message, [], :string
  attach_function :nexusq_vault_create, [:string, :string, :string], :int32
  attach_function :nexusq_vault_format_version, [:string], :int32

  def self.version
    nexusq_version
  end

  # Reports the provider compiled into the loaded library; it does not switch providers.
  def self.backend_info
    name = nexusq_backend_name
    { name: name, experimental: nexusq_backend_is_experimental != 0, native_available: name == "native-experimental" }
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
