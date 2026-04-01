#!/usr/bin/env ruby
# frozen_string_literal: true

require 'optparse'
require 'rexml/document'
require 'set'
require 'time'

module SentinelRPMConfigManifestGenerator
  Candidate = Struct.new(:path, :kind, :source_component, :logical_component, :indexed_by, keyword_init: true)

  module_function

  def run(argv)
    options = parse_args(argv)
    rpm_dir = options[:input]

    service_map = parse_active_services(File.join(rpm_dir, 'serviceImplementation.xml'))
    profile_paths = Dir.glob(File.join(rpm_dir, 'componentProfiles', '*.xml')).sort

    candidates = []
    profile_paths.each do |profile_path|
      xml = REXML::Document.new(File.read(profile_path))
      candidates.concat(profile_candidates(xml, profile_path, service_map))
    end

    deduped = {}
    candidates.each do |candidate|
      deduped[candidate.path] ||= candidate
    end

    filtered_candidates = options[:profile] == 'sentinel_phase1' ? sentinel_phase1_candidates(deduped.values) : deduped.values
    write_manifest(options[:output], filtered_candidates.sort_by(&:path), rpm_dir)
  end

  def parse_args(argv)
    options = {
      output: File.expand_path('generated_harvest_manifest_from_rpmconfig.txt', Dir.pwd),
      profile: 'full'
    }

    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby generate_harvest_manifest_from_rpmconfig.rb --input PROJECT.rpmConfig [--output manifest.txt]'
      opts.on('--input PATH', 'rpmConfig directory path') { |value| options[:input] = value }
      opts.on('--output PATH', 'Output manifest path') { |value| options[:output] = value }
      opts.on('--profile NAME', 'Manifest profile: full or sentinel_phase1') { |value| options[:profile] = value }
    end

    parser.parse!(argv)
    raise OptionParser::MissingArgument, '--input is required' unless options[:input]
    options
  end

  def parse_active_services(path)
    return [] unless File.exist?(path)

    services = []
    File.foreach(path) do |line|
      next unless line.include?('<service ')
      next unless line.include?(' enabled="true"')

      component = line[/source_component_name="([^"]+)"/, 1].to_s.strip
      logical = line[/source_logical_component="([^"]+)"/, 1].to_s.strip
      service_type = line[/service_type="([^"]+)"/, 1].to_s.strip
      next if component.empty? || logical.empty?

      services << {
        source_component_name: component,
        source_logical_component: logical,
        service_type: service_type,
        enabled: true
      }
    end

    services
  rescue => e
    warn "Failed to parse active services from #{path}: #{e.class}: #{e.message}"
    []
  end

  def profile_candidates(xml, profile_path, service_map)
    logical_metadata = extract_logical_metadata(xml)
    logicals = logical_metadata.keys
    matched_services = service_map.select { |service| logicals.include?(service[:source_logical_component]) }

    candidates = []
    candidates.concat(binding_candidates(matched_services, logical_metadata))
    candidates.concat(status_message_candidates(matched_services, logical_metadata))

    if matched_services.empty?
      logicals.each do |logical|
        logical_metadata.fetch(logical, {}).fetch(:bindings, []).each do |binding|
          candidates << Candidate.new(
            path: "#{logical}.#{binding}",
            kind: 'profile_logical_binding',
            source_component: File.basename(profile_path, '.xml'),
            logical_component: logical,
            indexed_by: []
          )
        end
      end
    end

    candidates
  end

  def extract_logical_metadata(xml)
    metadata = {}

    xml.elements.each('//logical_component') do |node|
      logical = node.attributes['logical_component_name'].to_s.strip
      next if logical.empty?

      metadata[logical] = {
        bindings: binding_names(xml, logical),
        status_states: status_state_metadata(node)
      }
    end

    metadata
  end

  def binding_candidates(matched_services, logical_metadata)
    candidates = []

    matched_services.each do |service|
      logical = service[:source_logical_component]
      logical_metadata.fetch(logical, {}).fetch(:bindings, []).each do |binding|
        candidates << Candidate.new(
          path: "#{service[:source_component_name]}.#{binding}",
          kind: 'active_service_binding',
          source_component: service[:source_component_name],
          logical_component: logical,
          indexed_by: []
        )
      end
    end

    candidates
  end

  def binding_names(xml, logical)
    names = Set.new

    xml.elements.each("//dynamic_state_variable[@owning_logical_component='#{logical}']") do |node|
      binding = node.attributes['state_center_binding'].to_s.strip
      names << binding unless binding.empty?
    end

    xml.elements.each("//state_variable[@owning_logical_component='#{logical}'][@state_center_binding]") do |node|
      binding = node.attributes['state_center_binding'].to_s.strip
      names << binding unless binding.empty?
    end

    names.to_a
  end

  def status_message_candidates(matched_services, logical_metadata)
    candidates = []

    matched_services.each do |service|
      logical = service[:source_logical_component]
      logical_metadata.fetch(logical, {}).fetch(:status_states, []).each do |status_state|
        candidates << Candidate.new(
          path: "#{service[:source_component_name]}.#{status_state[:name]}",
          kind: 'active_service_status_state',
          source_component: service[:source_component_name],
          logical_component: logical,
          indexed_by: status_state[:indexed_by]
        )
      end
    end

    candidates
  end

  def status_state_metadata(logical_node)
    states = []

    logical_node.get_elements('./status_messages/status_message').each do |status_message|
      appended = status_message.get_elements('./append_data_to_state_names').map { |node| node.attributes['state'].to_s.strip }.reject(&:empty?)
      updated_state_names(status_message).each do |state_name|
        states << { name: state_name, indexed_by: appended }
      end
    end

    states
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

  def write_manifest(path, candidates, rpm_dir)
    lines = []
    lines << "# Generated harvest manifest from rpmConfig"
    lines << "# Source package: #{rpm_dir}"
    lines << "# Generated at: #{Time.now.utc.iso8601}"
    lines << '#'
    lines << '# This file uses active service definitions from serviceImplementation.xml and'
    lines << '# state bindings/status-message states from installed component profiles.'
    lines << '#'
    lines << '# Paths marked indexed_by are profile states that expand at runtime using appended'
    lines << '# identifiers. Those usually need site-specific refinement.'
    lines << ''

    grouped = candidates.group_by(&:kind)
    grouped.keys.sort.each do |kind|
      lines << "# #{kind}"
      grouped[kind].sort_by(&:path).each do |candidate|
        meta = []
        meta << "source_component=#{candidate.source_component}" if candidate.source_component
        meta << "logical_component=#{candidate.logical_component}" if candidate.logical_component
        meta << "indexed_by=#{candidate.indexed_by.join('|')}" if candidate.indexed_by.any?
        lines << "# #{meta.join(' ')}" unless meta.empty?
        lines << candidate.path
      end
      lines << ''
    end

    File.write(path, lines.join("\n"))
  end

  def sentinel_phase1_candidates(candidates)
    candidates.select do |candidate|
      path = candidate.path

      keep_bridge_state?(path) ||
        keep_hue_state?(path)
    end
  end

  def keep_bridge_state?(path)
    [
      'Generic_component.APIServerStatus',
      'Generic_component.APILastError',
      'Generic_component.HarvestLastError',
      'Generic_component.HarvestStateCount',
      'Generic_component.HarvestStatus'
    ].include?(path)
  end

  def keep_hue_state?(path)
    return false unless path.start_with?('Hue Lighting Controller.')

    suffix = path.delete_prefix('Hue Lighting Controller.')
    return true if ['CurrentLightNumber', 'CurrentGroupNumber', 'UserName', 'DeviceType'].include?(suffix)
    return true if suffix.match?(/\AisLightOn_\d+\z/)
    return true if suffix.match?(/\AGroupisLightOn_\d+\z/)
    return true if suffix.match?(/\ABulbName_\d+\z/)
    return true if suffix.match?(/\AGroupName_\d+\z/)

    false
  end
end

SentinelRPMConfigManifestGenerator.run(ARGV)
