# frozen_string_literal: true

Gem::Specification.new do |s|
  s.name = "nexusq"
  s.version = "4.1.2"
  s.summary = "Ruby bindings for NEXUS-Q"
  s.description = "Thin FFI wrapper over the NEXUS-Q C SDK (libnexusq). " \
                  "No cryptography or business logic lives here."
  s.authors = ["lecodev-26"]
  s.licenses = ["MIT", "Apache-2.0"]
  s.homepage = "https://github.com/lecodev-26/nexus-q"
  s.files = ["lib/nexusq.rb", "examples/smoke/smoke.rb", "README.md"]
  s.required_ruby_version = ">= 3.0"

  s.add_runtime_dependency "ffi", "~> 1.15"
end
