#!/usr/bin/env ruby
# frozen_string_literal: true

require 'optparse'
require 'rexml/document'
require 'set'
require 'time'

module SentinelHarvestManifestGenerator
  Candidate = Struct.new(:path, :kind, :indexed_by, keyword_init: true)

  module_function

  def run(argv)
    options = parse_args(argv)
    xml = REXML::Document.new(File.read(options[:input]))

    candidates = []
    candidates.concat(binding_candidates(xml))
    candidates.concat(status_message_candidates(xml))

    deduped = {}
    candidates.each do |candidate|
      deduped[candidate.path] ||= candidate
    end

    write_manifest(options[:output], deduped.values.sort_by(&:path), options[:input])
  end

  def parse_args(argv)
    options = {
      output: File.expand_path('generated_harvest_manifest.txt', Dir.pwd)
    }

    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby generate_harvest_manifest_from_blueprint.rb --input PROFILE.xml [--output manifest.txt]'
      opts.on('--input PATH', 'Blueprint XML path') { |value| options[:input] = value }
      opts.on('--output PATH', 'Output manifest path') { |value| options[:output] = value }
    end

    parser.parse!(argv)

    raise OptionParser::MissingArgument, '--input is required' unless options[:input]

    options
  end

  def binding_candidates(xml)
    paths = []

    xml.elements.each('//dynamic_state_variable | //state_variable[@state_center_binding]') do |node|
      logical = node.attributes['owning_logical_component'].to_s.strip
      binding = node.attributes['state_center_binding'].to_s.strip
      next if logical.empty? || binding.empty?

      paths << Candidate.new(
        path: "#{logical}.#{binding}",
        kind: node.name == 'dynamic_state_variable' ? 'dynamic_binding' : 'bound_state_variable',
        indexed_by: []
      )
    end

    paths
  end

  def status_message_candidates(xml)
    candidates = []

    xml.elements.each('//logical_component') do |logical_component|
      logical_name = logical_component.attributes['logical_component_name'].to_s.strip
      next if logical_name.empty?

      logical_component.elements.each('./status_messages/status_message') do |status_message|
        appended = status_message.get_elements('./append_data_to_state_names').map { |node| node.attributes['state'].to_s.strip }.reject(&:empty?)

        updated_state_names(status_message).each do |state_name|
          candidates << Candidate.new(
            path: "#{logical_name}.#{state_name}",
            kind: 'status_message_state',
            indexed_by: appended
          )
        end
      end
    end

    candidates
  end

  def updated_state_names(status_message)
    names = Set.new

    status_message.elements.each('.//update') do |update|
      state = update.attributes['state'].to_s.strip
      names << state unless state.empty?
    end

    status_message.elements.each('.//update_state_variable') do |update|
      state = update.attributes['name'].to_s.strip
      names << state unless state.empty?
    end

    names.to_a
  end

  def write_manifest(path, candidates, source_path)
    lines = []
    lines << "# Generated harvest manifest"
    lines << "# Source XML: #{source_path}"
    lines << "# Generated at: #{Time.now.utc.iso8601}"
    lines << "#"
    lines << "# Uncomment or copy the paths you want into your deployed harvest manifest."
    lines << "# Paths marked 'indexed_by' usually become many runtime states because the profile appends"
    lines << "# identifiers such as central unit, zone, or output numbers to the state names."
    lines << ''

    grouped = candidates.group_by(&:kind)

    %w[dynamic_binding bound_state_variable status_message_state].each do |kind|
      next unless grouped[kind]

      lines << "# #{kind}"
      grouped[kind].sort_by(&:path).each do |candidate|
        if candidate.indexed_by.any?
          lines << "# indexed_by=#{candidate.indexed_by.join('|')}"
        end
        lines << candidate.path
      end
      lines << ''
    end

    File.write(path, lines.join("\n"))
  end
end

SentinelHarvestManifestGenerator.run(ARGV)
