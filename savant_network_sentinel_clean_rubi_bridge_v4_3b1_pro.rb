# frozen_string_literal: true

require 'base64'
require 'csv'
require 'fileutils'
require 'json'
require 'logger'
require 'net/http'
require 'openssl'
require 'open3'
require 'rexml/document'
require 'securerandom'
require 'shellwords'
require 'socket'
require 'thread'
require 'time'
require 'timeout'
require 'uri'
require 'webrick'

module SavantNetworkSentinelCleanRubiBridgeV40Pro
  VERSION = '4.3b1-pro'
  STORE_SCHEMA_VERSION = 5
  PASSWORD_ITERATIONS = 210_000
  LEGACY_PASSWORD_ITERATIONS = 20_000
  AUDIT_RETENTION_DAYS = 90
  ACTIVATION_PASSWORD_VALIDITY_SECONDS = 300
  ACTIVATION_EMAIL_RESEND_LIMIT = 3
  DEFAULT_DISCOVERY_SEEDS = %w[
    global.CurrentMinute
    global.rubi
    global.rubierror
    Generic_component.APILastError
    Generic_component.HarvestStatus
    Generic_component.HarvestLastError
    global.HostSoftwareVersion
    global.ResidenceSoftwareVersion
    global.OSVersion
    global.ProfileNamesAndDates
    global.FetchProfileProperties
    global.ChassisIPAddress
  ].freeze
  AUTO_MANIFEST_MODES = %w[ auto generated host_auto running_config ].freeze
  LIVE_DISCOVERY_REFRESH_SECONDS = 600

  class Bridge
    def initialize(bind_host:, port:, log_directory:, log_level:, users_file:, bootstrap_username:, bootstrap_password:, bootstrap_config_revision:, integrator_reset_flag:, harvest_state_list:, harvest_poll_seconds:, harvest_mode:, harvest_manifest_file:, harvest_max_states:, use_https: '0', tls_cert_file: '', tls_key_file: '')
      @bind_host = bind_host.to_s.strip.empty? ? '0.0.0.0' : bind_host.to_s.strip
      @port = port.to_i
      @port = 42_042 if @port <= 0
      @log_directory = log_directory.to_s.strip.empty? ? '/tmp' : log_directory.to_s.strip
      @users_file = users_file.to_s.strip.empty? ? File.join(@log_directory, 'sentinel_users.json') : users_file.to_s.strip
      @pid_file = File.join(File.dirname(@users_file), 'sentinel_bridge.pid')
      @bootstrap_username = bootstrap_username.to_s.strip.empty? ? 'installer' : bootstrap_username.to_s.strip
      @bootstrap_password = bootstrap_password.to_s.strip.empty? ? 'change_me_now' : bootstrap_password.to_s
      @bootstrap_config_revision = bootstrap_config_revision.to_s.strip.empty? ? 'v1' : bootstrap_config_revision.to_s.strip
      @integrator_reset_flag = integrator_reset_flag.to_s.strip.empty? ? '0' : integrator_reset_flag.to_s.strip
      @harvest_state_list_raw = harvest_state_list.to_s
      @harvest_mode = normalize_harvest_mode(harvest_mode)
      @harvest_manifest_file = harvest_manifest_file.to_s.strip
      @harvest_max_states = harvest_max_states.to_i
      @harvest_max_states = 7_000 if @harvest_max_states <= 0
      @harvest_poll_seconds = harvest_poll_seconds.to_i
      @harvest_poll_seconds = 15 if @harvest_poll_seconds <= 0
      @use_https = truthy?(use_https)
      sentinel_root = File.dirname(@users_file)
      @tls_cert_file = tls_cert_file.to_s.strip.empty? ? File.join(sentinel_root, 'sentinel_bridge.crt') : tls_cert_file.to_s.strip
      @tls_key_file = tls_key_file.to_s.strip.empty? ? File.join(sentinel_root, 'sentinel_bridge.key') : tls_key_file.to_s.strip
      @tls_fingerprint = nil
      @tls_certificate = nil
      @sclibridge_path = detect_sclibridge_path
      @mutex = Mutex.new
      @sessions = {}
      @state_cache = {}
      @recent_events = []
      @users = {}
      @monitoring_profile = default_monitoring_profile
      @supported_actions = default_supported_actions
      @policy = default_policy
      @server_started = false
      @site_name = 'Savant Network Sentinel'
      @resolved_harvest_state_list = []
      @resolved_harvest_signature = nil
      @manifest_cache = { key: nil, paths: [] }
      @manifest_refresh_interval = 60
      @last_manifest_refresh_at = Time.at(0)
      @generated_manifest_file = File.join(File.dirname(@users_file), 'generated_harvest_manifest.txt')
      @last_live_discovery_at = Time.at(0)
      @host_runtime_cache = {
        summary: { at: Time.at(0), payload: nil },
        detailed: { at: Time.at(0), payload: nil }
      }
      @host_runtime_summary_ttl = 180
      @host_runtime_detailed_ttl = 20
      @bridge_catalog_file = File.join(File.dirname(@users_file), 'sentinel_bridge_catalog.json')
      @bridge_catalog_cache = nil
      @bridge_catalog_cache_at = Time.at(0)
      @bridge_catalog_ttl = 30
      @harvest_cursor = 0
      @harvest_cycle_count = 0
      @audit_log_file = File.join(File.dirname(@users_file), 'sentinel_audit.jsonl')
      @last_audit_prune_at = Time.at(0)
      @terminal_sessions = {}
      @terminal_session_timeout_seconds = 900
      setup_logger(log_level)
      load_store
      reconcile_bootstrap_integrator
      prune_audit_log_if_needed(force: true)
      start_server
      start_harvest_thread
    end

    def stop
      @server&.shutdown
      @server = nil
      @server_thread&.kill
      @server_thread = nil
      @harvest_thread&.kill
      @harvest_thread = nil
      release_pid_file
      emit_status('stopped', '')
    rescue => e
      @logger.error("stop failed #{e.class}: #{e.message}")
    end

    def reload(bind_host:, port:, log_directory:, log_level:, users_file:, bootstrap_username:, bootstrap_password:, bootstrap_config_revision:, integrator_reset_flag:, harvest_state_list:, harvest_poll_seconds:, harvest_mode:, harvest_manifest_file:, harvest_max_states:, use_https: '0', tls_cert_file: '', tls_key_file: '')
      stop
      initialize(
        bind_host: bind_host,
        port: port,
        log_directory: log_directory,
        log_level: log_level,
        users_file: users_file,
        bootstrap_username: bootstrap_username,
        bootstrap_password: bootstrap_password,
        bootstrap_config_revision: bootstrap_config_revision,
        integrator_reset_flag: integrator_reset_flag,
        harvest_state_list: harvest_state_list,
        harvest_poll_seconds: harvest_poll_seconds,
        harvest_mode: harvest_mode,
        harvest_manifest_file: harvest_manifest_file,
        harvest_max_states: harvest_max_states,
        use_https: use_https,
        tls_cert_file: tls_cert_file,
        tls_key_file: tls_key_file
      )
    end

    def ingest(event_type, payload)
      item = {
        'type' => event_type,
        'payload' => payload,
        'at' => Time.now.utc.iso8601
      }
      @mutex.synchronize do
        @recent_events << item
        @recent_events = @recent_events.last(250)
        @state_cache[event_type] = item
      end
    end

    def emit_status(status, error)
      puts ['sentinel_api', status, @bind_host, @port, @users.length, active_sessions_count, error.to_s.gsub(',', ';')].join(',')
      STDOUT.flush
    rescue => e
      @logger.error("emit_status failed #{e.class}: #{e.message}")
    end

    private

    def start_server
      options = {
        BindAddress: @bind_host,
        Port: @port,
        Logger: @logger,
        AccessLog: []
      }
      if @use_https
        require 'webrick/https'
        certificate, private_key = ensure_tls_material
        options.merge!(
          SSLEnable: true,
          SSLCertificate: certificate,
          SSLPrivateKey: private_key,
          SSLVerifyClient: OpenSSL::SSL::VERIFY_NONE
        )
      end
      @server = WEBrick::HTTPServer.new(options)
      @server_started = true
      mount_routes
      @server_thread = Thread.new { @server.start }
      register_pid_file
      emit_status('running', '')
      @logger.info("bridge listening on #{transport_scheme}://#{@bind_host}:#{@port}")
    rescue => e
      emit_status('error', "#{e.class}:#{e.message}")
      raise
    end

    def register_pid_file
      return if @pid_file.to_s.strip.empty?

      FileUtils.mkdir_p(File.dirname(@pid_file))
      File.open(@pid_file, 'w', 0o600) do |f|
        f.write("#{Process.pid}\n")
      end
      File.chmod(0o600, @pid_file) rescue nil
    rescue => e
      @logger.error("register_pid_file failed #{e.class}: #{e.message}")
    end

    def release_pid_file
      return if @pid_file.to_s.strip.empty?
      return unless File.exist?(@pid_file)

      existing = File.read(@pid_file).to_s.strip
      return unless existing.empty? || existing == Process.pid.to_s

      File.delete(@pid_file)
    rescue => e
      @logger.error("release_pid_file failed #{e.class}: #{e.message}")
    end

    def mount_routes
      @server.mount_proc('/') do |_req, res|
        json(res, 200, {
          status: 'ok',
          message: 'Savant Network Sentinel bridge is running.',
          version: VERSION,
          transport_scheme: transport_scheme,
          tls_enabled: @use_https ? true : false,
          tls_fingerprint: @tls_fingerprint,
          endpoints: [
            '/health',
            '/api/v1/auth/login',
            '/api/v1/auth/me',
            '/api/v1/auth/change-password',
            '/api/v1/acknowledgements/role',
            '/api/v1/acknowledgements/monitoring',
            '/api/v1/pairing/authorize-integrator',
            '/api/v1/site/config',
            '/api/v1/site/status',
            '/api/v1/site/discovery',
            '/api/v1/site/host-runtime',
            '/api/v1/tools/terminal/open',
            '/api/v1/tools/terminal/run',
            '/api/v1/tools/terminal/close',
            '/api/v1/tools/host/reboot',
            '/api/v1/tools/doorbell/status',
            '/api/v1/tools/doorbell/upload',
            '/api/v1/tools/doorbell/apply-sample',
            '/api/v1/tools/doorbell/sample-audio',
            '/api/v1/audit',
            '/api/v1/admin/users',
            '/api/v1/admin/home-admin-activation',
            '/api/v1/admin/home-admin-activation/resend',
            '/api/v1/admin/home-admin-activation/cancel',
            '/api/v1/admin/monitoring',
            '/api/v1/admin/catalog',
            '/api/v1/home/revoke-integrator',
            '/api/v1/admin/audit'
          ]
        })
      end

      @server.mount_proc('/health') do |_req, res|
        json(res, 200, {
          status: 'ok',
          version: VERSION,
          pid: Process.pid,
          pid_file: @pid_file,
          transport_scheme: transport_scheme,
          tls_enabled: @use_https ? true : false,
          tls_fingerprint: @tls_fingerprint,
          bind_host: @bind_host,
          port: @port,
          users_loaded: @users.length,
          sessions_active: active_sessions_count,
          harvest_state_count: harvested_state_count,
          resolved_state_count: resolved_harvest_state_count
        })
      end

      @server.mount_proc('/api/v1/auth/login') do |req, res|
        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        payload = parse_json(req)
        username = payload['username'].to_s
        password = payload['password'].to_s
        blocked_reason = integrator_login_block_reason(username)
        if blocked_reason
          audit_event('auth.login.failure', actor: username, details: { source: request_source(req), reason: blocked_reason })
          json(res, 403, { error: blocked_reason, pairing_state: pairing_state_payload })
          next
        end
        session = login(username, password)
        if session
          audit_event('auth.login.success', actor: username, details: { source: request_source(req) })
          json(res, 200, session_response(session))
        else
          audit_event('auth.login.failure', actor: username, details: { source: request_source(req) })
          json(res, 401, { error: 'invalid_credentials' })
        end
      end

      @server.mount_proc('/api/v1/auth/me') do |req, res|
        auth = authenticate(req)
        unless auth
          json(res, 401, { error: 'unauthorized' })
          next
        end

        audit_access(auth, req, 'auth.me')
        json(res, 200, session_response(auth))
      end

      @server.mount_proc('/api/v1/auth/change-password') do |req, res|
        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        auth = authenticate(req)
        unless auth
          json(res, 401, { error: 'unauthorized' })
          next
        end

        payload = parse_json(req)
        current_password = payload['current_password'].to_s
        new_password = payload['new_password'].to_s
        changed = change_password(
          username: auth['username'],
          current_password: current_password,
          new_password: new_password,
          force_clear_bootstrap: true
        )
        if changed == :ok
          audit_event('auth.password_changed', actor: auth['username'], details: { source: request_source(req), forced_rotation: auth['requires_password_change'] ? true : false })
          refreshed = current_session(auth['token'])
          json(res, 200, session_response(refreshed || auth))
        else
          audit_event('auth.password_change_failed', actor: auth['username'], details: { source: request_source(req), reason: changed.to_s })
          json(res, 400, {
            error: changed == :weak_password ? 'weak_password' : 'password_change_failed',
            password_policy: password_policy_summary
          })
        end
      end

      @server.mount_proc('/api/v1/acknowledgements/monitoring') do |req, res|
        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        auth = authenticate(req)
        unless auth
          json(res, 401, { error: 'unauthorized' })
          next
        end

        acknowledge_monitoring(auth['username'])
        refresh_sessions_for_user(
          auth['username'],
          requires_password_change: auth['requires_password_change'],
          acknowledged_monitoring_version: @policy['monitoring_profile_version'],
          role_acknowledged_at: auth['role_acknowledged_at']
        )
        audit_event('monitoring.acknowledged', actor: auth['username'], details: {
          role: auth['role'],
          monitoring_profile_version: @policy['monitoring_profile_version'],
          source: request_source(req)
        })
        refreshed = current_session(auth['token'])
        json(res, 200, session_response(refreshed || auth))
      end

      @server.mount_proc('/api/v1/acknowledgements/role') do |req, res|
        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        auth = authenticate(req)
        unless auth
          json(res, 401, { error: 'unauthorized' })
          next
        end

        payload = parse_json(req)
        unless payload['accepted'] == true
          json(res, 400, { error: 'role_acknowledgement_required', role_warning: role_warning_for(auth['role']) })
          next
        end

        acknowledge_role(auth['username'])
        refresh_sessions_for_user(
          auth['username'],
          requires_password_change: auth['requires_password_change'],
          acknowledged_monitoring_version: auth['acknowledged_monitoring_version'],
          role_acknowledged_at: @users[auth['username']]['role_acknowledged_at']
        )
        audit_event('role.acknowledged', actor: auth['username'], details: {
          role: auth['role'],
          source: request_source(req)
        })
        refreshed = current_session(auth['token'])
        json(res, 200, session_response(refreshed || auth))
      end

      @server.mount_proc('/api/v1/pairing/authorize-integrator') do |req, res|
        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        auth = authenticate(req)
        unless auth && auth['role'] == 'home_admin'
          json(res, 403, { error: 'forbidden' })
          next
        end
        if auth['requires_password_change']
          json(res, 403, { error: 'password_change_required' })
          next
        end
        if requires_role_acknowledgement?(auth)
          json(res, 403, { error: 'role_acknowledgement_required', role_warning: role_warning_for(auth['role']) })
          next
        end
        if requires_monitoring_acknowledgement?(auth)
          json(res, 403, { error: 'monitoring_acknowledgement_required' })
          next
        end

        authorize_integrator(actor: auth['username'])
        audit_event('pairing.integrator_authorized', actor: auth['username'], details: {
          source: request_source(req)
        })
        refreshed = current_session(auth['token'])
        json(res, 200, {
          paired: pairing_complete?,
          pairing_state: pairing_state_payload,
          session: session_response(refreshed || auth)
        })
      end

      @server.mount_proc('/api/v1/site/config') do |req, res|
        auth = authenticate(req)
        unless auth
          json(res, 401, { error: 'unauthorized' })
          next
        end
        unless pairing_complete?
          audit_access(auth, req, 'site.config.initialization')
          json(res, 200, {
            site_name: @site_name,
            bridge_version: VERSION,
            bridge_pid: Process.pid,
            bridge_pid_file: @pid_file,
            initialization_mode: true,
            pairing_state: pairing_state_payload
          })
          next
        end
        unless action_allowed?(auth, 'site.config')
          json(res, 403, { error: 'forbidden' })
          next
        end

        audit_access(auth, req, 'site.config')
        json(res, 200, {
          site_name: @site_name,
          bridge_version: VERSION,
          bridge_pid: Process.pid,
          bridge_pid_file: @pid_file,
          api_port: @port,
          bind_host: @bind_host,
          transport_scheme: transport_scheme,
          tls_enabled: @use_https ? true : false,
          tls_fingerprint: @tls_fingerprint,
          active_config_filename: active_config_filename,
          harvest_state_count: harvested_state_count,
          harvest_mode: @harvest_mode,
          harvest_manifest_file: @harvest_manifest_file,
          resolved_manifest_source: resolved_manifest_source,
          resolved_harvest_state_count: resolved_harvest_state_count,
          generator_debug: cached_generator_debug_payload,
          host_runtime: host_runtime_payload(detailed: false),
          access: effective_access_summary(auth)
        })
      end

      @server.mount_proc('/api/v1/site/status') do |req, res|
        auth = authenticate(req)
        unless auth
          json(res, 401, { error: 'unauthorized' })
          next
        end
        unless pairing_complete?
          audit_access(auth, req, 'site.status.initialization')
          json(res, 200, {
            generated_at: Time.now.utc.iso8601,
            bridge_version: VERSION,
            bridge: {
              version: VERSION,
              pid: Process.pid,
              pid_file: @pid_file,
              bind_host: @bind_host,
              port: @port,
              harvest_mode: @harvest_mode
            },
            initialization_mode: true,
            pairing_state: pairing_state_payload,
            recent_events: @mutex.synchronize { @recent_events.last(25) }
          })
          next
        end
        unless action_allowed?(auth, 'site.status')
          json(res, 403, { error: 'forbidden' })
          next
        end

        audit_access(auth, req, 'site.status')
        json(res, 200, {
          generated_at: Time.now.utc.iso8601,
          bridge_version: VERSION,
          bridge: {
            version: VERSION,
            pid: Process.pid,
            pid_file: @pid_file,
            bind_host: @bind_host,
            port: @port,
            harvest_mode: @harvest_mode,
            transport_scheme: transport_scheme,
            tls_enabled: @use_https ? true : false,
            tls_fingerprint: @tls_fingerprint
          },
          metrics: {
            users_loaded: @users.length,
            sessions_active: active_sessions_count,
            states_cached: @state_cache.length,
            harvested_states: harvested_state_count,
            resolved_harvest_states: resolved_harvest_state_count
          },
          active_config_filename: active_config_filename,
          recent_events: @mutex.synchronize { @recent_events.last(50) },
          host_runtime: host_runtime_payload(detailed: false),
          bridge_catalog: bridge_catalog_payload,
          access: effective_access_summary(auth),
          harvested_statecenter: harvested_statecenter_for(auth)
        })
      end

      @server.mount_proc('/api/v1/site/discovery') do |req, res|
        auth = authenticate(req)
        unless auth
          json(res, 401, { error: 'unauthorized' })
          next
        end
        unless pairing_complete?
          audit_access(auth, req, 'site.discovery.initialization')
          json(res, 200, {
            generated_at: Time.now.utc.iso8601,
            version: VERSION,
            initialization_mode: true,
            pairing_state: pairing_state_payload,
            resolved_harvest_state_count: 0,
            resolved_harvest_states: []
          })
          next
        end
        unless action_allowed?(auth, 'site.discovery')
          json(res, 403, { error: 'forbidden' })
          next
        end

        resolved = resolve_harvest_state_list
        visible = auth['role'] == 'integrator' ? resolved : resolved.select { |path| state_visible_to_session?(auth, path) }
        audit_access(auth, req, 'site.discovery')
        json(res, 200, {
          generated_at: Time.now.utc.iso8601,
          version: VERSION,
          harvest_mode: @harvest_mode,
          harvest_manifest_file: @harvest_manifest_file,
          resolved_manifest_source: resolved_manifest_source,
          resolved_harvest_state_count: visible.length,
          resolved_harvest_states: visible,
          generator_debug: cached_generator_debug_payload,
          discovery_notes: [
            'v4.3b1-pro prefers live StateCenter discovery through sclibridge statenames and refreshes it infrequently to respect host performance.',
            'When live discovery is unavailable, the auto-generated manifest falls back to the running userConfig.rpmConfig service map and installed component profiles.'
          ]
        })
      end

      @server.mount_proc('/api/v1/site/host-runtime') do |req, res|
        auth = authenticate(req)
        unless auth
          json(res, 401, { error: 'unauthorized' })
          next
        end
        unless pairing_complete?
          audit_access(auth, req, 'site.host_runtime.initialization')
          json(res, 200, {
            generated_at: Time.now.utc.iso8601,
            initialization_mode: true,
            pairing_state: pairing_state_payload
          })
          next
        end
        unless action_allowed?(auth, 'site.status')
          json(res, 403, { error: 'forbidden' })
          next
        end

        detail_param = req.query['detail'].to_s.strip.downcase
        detailed = %w[1 true full detailed debug].include?(detail_param)

        audit_access(auth, req, detailed ? 'site.host_runtime.detailed' : 'site.host_runtime.summary')
        json(res, 200, host_runtime_payload(detailed: detailed))
      end

      @server.mount_proc('/api/v1/tools/terminal/open') do |req, res|
        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        auth = authenticate(req)
        unless auth && can_access_host_tools?(auth)
          json(res, 403, { error: 'forbidden' })
          next
        end

        purge_expired_terminal_sessions!
        session_id = SecureRandom.hex(12)
        @mutex.synchronize do
          @terminal_sessions[session_id] = {
            'id' => session_id,
            'username' => auth['username'],
            'role' => auth['role'],
            'opened_at' => Time.now.utc.iso8601,
            'last_seen_at' => Time.now.utc.iso8601
          }
        end
        audit_event('tools.terminal.open', actor: auth['username'], details: { session_id: session_id, source: request_source(req) })
        json(res, 200, { session: @terminal_sessions[session_id] })
      end

      @server.mount_proc('/api/v1/tools/terminal/run') do |req, res|
        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        auth = authenticate(req)
        unless auth && can_access_host_tools?(auth)
          json(res, 403, { error: 'forbidden' })
          next
        end

        payload = parse_json(req)
        session_id = payload['session_id'].to_s
        command = payload['command'].to_s
        sudo_password = payload['sudo_password'].to_s

        terminal_session = touch_terminal_session(session_id: session_id, actor: auth['username'])
        unless terminal_session
          json(res, 404, { error: 'terminal_session_not_found' })
          next
        end

        unless terminal_command_allowed?(command)
          json(res, 403, { error: 'terminal_command_not_allowed' })
          next
        end

        execution = execute_terminal_command(
          command: command,
          sudo_password: sudo_password,
          actor: auth['username']
        )
        audit_event('tools.terminal.run', actor: auth['username'], details: {
          session_id: session_id,
          command: command,
          exit_code: execution[:exit_code],
          timed_out: execution[:timed_out] ? true : false
        })
        json(res, 200, { execution: execution })
      end

      @server.mount_proc('/api/v1/tools/terminal/close') do |req, res|
        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        auth = authenticate(req)
        unless auth && can_access_host_tools?(auth)
          json(res, 403, { error: 'forbidden' })
          next
        end

        payload = parse_json(req)
        session_id = payload['session_id'].to_s
        removed = remove_terminal_session(session_id: session_id, actor: auth['username'])
        if removed
          audit_event('tools.terminal.close', actor: auth['username'], details: { session_id: session_id })
          json(res, 200, { closed: true })
        else
          json(res, 404, { error: 'terminal_session_not_found' })
        end
      end

      @server.mount_proc('/api/v1/tools/host/reboot') do |req, res|
        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        auth = authenticate(req)
        unless auth && can_access_host_tools?(auth)
          json(res, 403, { error: 'forbidden' })
          next
        end

        payload = parse_json(req)
        mode = payload['mode'].to_s.strip.downcase
        sudo_password = payload['sudo_password'].to_s
        warning_acknowledged = payload['warning_acknowledged'] ? true : false
        second_confirmation = payload['second_confirmation'] ? true : false

        unless warning_acknowledged && second_confirmation
          json(res, 400, { error: 'double_confirmation_required' })
          next
        end
        if sudo_password.strip.empty?
          json(res, 400, { error: 'sudo_password_required' })
          next
        end

        reboot = request_host_reboot(mode: mode, sudo_password: sudo_password, actor: auth['username'])
        if reboot[:ok]
          audit_event('tools.host.reboot', actor: auth['username'], details: {
            mode: reboot[:mode],
            method: reboot[:method],
            source: request_source(req)
          })
          json(res, 202, reboot)
        else
          json(res, 400, reboot)
        end
      end

      @server.mount_proc('/api/v1/tools/doorbell/status') do |req, res|
        unless req.request_method == 'GET'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        auth = authenticate(req)
        unless auth && can_access_host_tools?(auth)
          json(res, 403, { error: 'forbidden' })
          next
        end

        payload = doorbell_status_payload
        audit_event('tools.doorbell.status', actor: auth['username'], details: {
          source: request_source(req),
          references_detected: payload[:references_detected].length,
          requires_sudo_for_patch: payload[:requires_sudo_for_patch] ? true : false
        })
        json(res, 200, payload)
      end

      @server.mount_proc('/api/v1/tools/doorbell/upload') do |req, res|
        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        auth = authenticate(req)
        unless auth && can_access_host_tools?(auth)
          json(res, 403, { error: 'forbidden' })
          next
        end

        payload = parse_json(req)
        result = handle_custom_doorbell_upload(
          file_name: payload['file_name'].to_s,
          wav_base64: payload['wav_base64'].to_s,
          sudo_password: payload['sudo_password'].to_s,
          actor: auth['username'],
          auto_apply: payload.key?('auto_apply') ? (payload['auto_apply'] ? true : false) : true
        )

        if result[:ok]
          audit_event('tools.doorbell.upload', actor: auth['username'], details: {
            source: request_source(req),
            file_name: result[:uploaded_file_name],
            uploaded_path: result[:uploaded_file_path],
            applied: result[:applied] ? true : false,
            replaced_references: result[:replaced_references].to_i
          })
          json(res, 200, result)
        else
          json(res, result[:http_status].to_i.positive? ? result[:http_status].to_i : 400, result)
        end
      end

      @server.mount_proc('/api/v1/tools/doorbell/apply-sample') do |req, res|
        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        auth = authenticate(req)
        unless auth && can_access_host_tools?(auth)
          json(res, 403, { error: 'forbidden' })
          next
        end

        payload = parse_json(req)
        result = handle_builtin_doorbell_apply(
          sample_id: payload['sample_id'].to_s,
          sudo_password: payload['sudo_password'].to_s,
          actor: auth['username']
        )
        if result[:ok]
          audit_event('tools.doorbell.apply_sample', actor: auth['username'], details: {
            source: request_source(req),
            sample_id: payload['sample_id'].to_s,
            sample_name: result[:sample_name],
            replaced_references: result[:replaced_references].to_i
          })
          json(res, 200, result)
        else
          json(res, result[:http_status].to_i.positive? ? result[:http_status].to_i : 400, result)
        end
      end

      @server.mount_proc('/api/v1/tools/doorbell/sample-audio') do |req, res|
        unless req.request_method == 'GET'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        auth = authenticate(req)
        unless auth && can_access_host_tools?(auth)
          json(res, 403, { error: 'forbidden' })
          next
        end

        sample_id = req.query['sample_id'].to_s.strip
        result = handle_builtin_doorbell_preview(sample_id: sample_id)
        if result[:ok]
          audit_event('tools.doorbell.preview', actor: auth['username'], details: {
            source: request_source(req),
            sample_id: sample_id,
            sample_name: result[:sample_name]
          })
          res.status = 200
          res['Content-Type'] = result[:content_type].to_s.empty? ? 'audio/wav' : result[:content_type].to_s
          res['Cache-Control'] = 'no-store'
          res['Content-Disposition'] = "inline; filename=\"#{result[:file_name]}\""
          res.body = result[:bytes].to_s
        else
          json(res, result[:http_status].to_i.positive? ? result[:http_status].to_i : 400, result)
        end
      end

      @server.mount_proc('/api/v1/admin/users') do |req, res|
        auth = authenticate(req)
        unless auth && can_access_user_management?(auth)
          json(res, 403, { error: 'forbidden' })
          next
        end

        case req.request_method
        when 'GET'
          audit_access(auth, req, 'admin.users.list')
          json(res, 200, { users: visible_users_for(auth).map { |user| sanitize_user(user) } })
        when 'POST'
          payload = parse_json(req)
          username = payload.fetch('username', '').to_s.strip
          target_role = normalize_role(payload.fetch('role', 'home_user'))
          if target_role == 'home_admin'
            json(res, 403, { error: 'home_admin_activation_required' })
            next
          end
          unless can_manage_role?(auth, target_role)
            json(res, 403, { error: 'forbidden' })
            next
          end
          temporary_password_requested = payload['temporary_password'] ? true : false
          temporary_password_requested = true if payload['use_temporary_password']
          requires_password_change = if payload.key?('requires_password_change')
                                       payload['requires_password_change'] ? true : false
                                     else
                                       temporary_password_requested
                                     end
          email = payload['email'].to_s.strip
          if !email.empty? && !valid_email?(email)
            json(res, 400, { error: 'invalid_email' })
            next
          end

          provided_password = payload.fetch('password', '').to_s
          generated_temporary_password = nil
          if temporary_password_requested && provided_password.strip.empty?
            generated_temporary_password = activation_password
          end
          effective_password = generated_temporary_password || provided_password

          created = create_user(
            username: username,
            password: effective_password,
            role: target_role,
            enabled: payload.fetch('enabled', true) ? true : false,
            permissions: payload['permissions'],
            requires_password_change: requires_password_change
          )
          case created
          when :ok
            unless email.empty?
              if @users[username]
                @users[username]['email'] = email
                persist_store
              end
            end

            response = { created: true }
            if temporary_password_requested
              temporary_password = generated_temporary_password || effective_password
              response[:temporary_password] = temporary_password
              response[:requires_password_change] = requires_password_change ? true : false

              delivery = user_temporary_password_delivery_payload(
                username: username,
                role: target_role,
                email: email,
                password: temporary_password
              )
              delivery_method = 'manual'
              unless email.empty?
                if send_user_temporary_password_email(username: username, role: target_role, email: email, password: temporary_password)
                  delivery_method = 'host_email'
                else
                  delivery_method = 'mail_app'
                end
              end
              response[:delivery_method] = delivery_method
              response[:activation_delivery] = delivery
            end

            audit_event('admin.user.created', actor: auth['username'], details: {
              username: username,
              role: target_role,
              enabled: payload.fetch('enabled', true) ? true : false,
              temporary_password: temporary_password_requested,
              requires_password_change: requires_password_change ? true : false,
              email_provided: !email.empty?
            })
            json(res, 201, response)
          when :singleton_role_taken
            json(res, 409, { error: 'singleton_role_taken', message: 'Only one integrator and one home admin may exist per installation.' })
          when :weak_password
            json(res, 400, { error: 'weak_password', password_policy: password_policy_summary })
          else
            json(res, 400, { error: 'invalid_user_payload' })
          end
        when 'PATCH'
          payload = parse_json(req)
          existing = @users[payload.fetch('username', '').to_s]
          unless existing && can_manage_user?(auth, existing)
            json(res, 403, { error: 'forbidden' })
            next
          end
          requested_role = payload['role'] ? normalize_role(payload['role']) : existing['role']
          if existing['role'].to_s != 'home_admin' && requested_role == 'home_admin'
            json(res, 403, { error: 'home_admin_activation_required' })
            next
          end
          unless can_manage_role?(auth, requested_role)
            json(res, 403, { error: 'forbidden' })
            next
          end
          updated = update_user(
            username: payload.fetch('username', '').to_s,
            password: payload['password'],
            role: requested_role,
            enabled: payload.key?('enabled') ? !!payload['enabled'] : nil,
            permissions: payload['permissions']
          )
          case updated
          when true
            audit_event('admin.user.updated', actor: auth['username'], details: { username: payload.fetch('username', '').to_s, password_reset: !payload['password'].to_s.empty?, role: requested_role, enabled: payload.key?('enabled') ? !!payload['enabled'] : nil })
            json(res, 200, { updated: true })
          when :singleton_role_taken
            json(res, 409, { error: 'singleton_role_taken', message: 'Only one integrator and one home admin may exist per installation.' })
          when :weak_password
            json(res, 400, { error: 'weak_password', password_policy: password_policy_summary })
          else
            json(res, 404, { error: 'user_not_found' })
          end
        when 'DELETE'
          payload = parse_json(req)
          target = @users[payload.fetch('username', '').to_s]
          unless target && can_manage_user?(auth, target)
            json(res, 403, { error: 'forbidden' })
            next
          end
          deleted = delete_user(payload.fetch('username', '').to_s)
          if deleted
            audit_event('admin.user.deleted', actor: auth['username'], details: { username: payload.fetch('username', '').to_s })
            json(res, 200, { deleted: true })
          else
            json(res, 404, { error: 'user_not_found' })
          end
        else
          json(res, 405, { error: 'method_not_allowed' })
        end
      end

      @server.mount_proc('/api/v1/admin/home-admin-activation') do |req, res|
        auth = authenticate(req)
        unless auth && auth['role'] == 'integrator' && !auth['requires_password_change']
          json(res, 403, { error: 'forbidden' })
          next
        end
        if requires_role_acknowledgement?(auth)
          json(res, 403, { error: 'role_acknowledgement_required', role_warning: role_warning_for(auth['role']) })
          next
        end
        if requires_monitoring_acknowledgement?(auth)
          json(res, 403, { error: 'monitoring_acknowledgement_required' })
          next
        end

        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        payload = parse_json(req)
        result = initiate_home_admin_activation(
          username: payload.fetch('username', '').to_s,
          email: payload.fetch('email', '').to_s
        )

        case result[:status]
        when :ok
          audit_event('activation.home_admin.created', actor: auth['username'], details: {
            username: payload.fetch('username', '').to_s,
            email: payload.fetch('email', '').to_s,
            delivery: result[:delivery_method] || 'host_email'
          })
          json(res, 201, {
            created: true,
            delivery_method: result[:delivery_method] || 'host_email',
            activation_delivery: result[:activation_delivery],
            pairing_state: pairing_state_payload
          })
        when :manual_delivery_required
          audit_event('activation.home_admin.created', actor: auth['username'], details: {
            username: payload.fetch('username', '').to_s,
            email: payload.fetch('email', '').to_s,
            delivery: 'manual_mail_app'
          })
          json(res, 201, {
            created: true,
            delivery_method: 'mail_app',
            activation_delivery: result[:activation_delivery],
            pairing_state: pairing_state_payload
          })
        when :reset_required
          json(res, 409, { error: 'sentinel_reset_required', pairing_state: pairing_state_payload })
        when :already_exists
          json(res, 409, { error: 'home_admin_exists', pairing_state: pairing_state_payload })
        when :email_delivery_failed
          json(res, 502, { error: 'activation_email_failed', pairing_state: pairing_state_payload })
        else
          json(res, 400, { error: result[:status].to_s, pairing_state: pairing_state_payload })
        end
      end

      @server.mount_proc('/api/v1/admin/home-admin-activation/resend') do |req, res|
        auth = authenticate(req)
        unless auth && auth['role'] == 'integrator' && !auth['requires_password_change']
          json(res, 403, { error: 'forbidden' })
          next
        end
        if requires_role_acknowledgement?(auth)
          json(res, 403, { error: 'role_acknowledgement_required', role_warning: role_warning_for(auth['role']) })
          next
        end
        if requires_monitoring_acknowledgement?(auth)
          json(res, 403, { error: 'monitoring_acknowledgement_required' })
          next
        end

        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        payload = parse_json(req)
        result = resend_home_admin_activation(email: payload['email'])
        case result[:status]
        when :ok
          audit_event('activation.home_admin.resent', actor: auth['username'], details: {
            email: result[:email],
            resend_count: result[:resend_count],
            delivery: result[:delivery_method] || 'host_email'
          })
          json(res, 200, {
            resent: true,
            delivery_method: result[:delivery_method] || 'host_email',
            activation_delivery: result[:activation_delivery],
            pairing_state: pairing_state_payload
          })
        when :manual_delivery_required
          audit_event('activation.home_admin.resent', actor: auth['username'], details: {
            email: result[:email],
            resend_count: result[:resend_count],
            delivery: 'manual_mail_app'
          })
          json(res, 200, {
            resent: true,
            delivery_method: 'mail_app',
            activation_delivery: result[:activation_delivery],
            pairing_state: pairing_state_payload
          })
        when :reset_required
          json(res, 409, { error: 'sentinel_reset_required', pairing_state: pairing_state_payload })
        when :email_delivery_failed
          json(res, 502, { error: 'activation_email_failed', pairing_state: pairing_state_payload })
        else
          json(res, 400, { error: result[:status].to_s, pairing_state: pairing_state_payload })
        end
      end

      @server.mount_proc('/api/v1/admin/home-admin-activation/cancel') do |req, res|
        auth = authenticate(req)
        unless auth && auth['role'] == 'integrator' && !auth['requires_password_change']
          json(res, 403, { error: 'forbidden' })
          next
        end
        if requires_role_acknowledgement?(auth)
          json(res, 403, { error: 'role_acknowledgement_required', role_warning: role_warning_for(auth['role']) })
          next
        end
        if requires_monitoring_acknowledgement?(auth)
          json(res, 403, { error: 'monitoring_acknowledgement_required' })
          next
        end

        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        cancelled = cancel_home_admin_activation
        if cancelled
          audit_event('activation.home_admin.cancelled', actor: auth['username'], details: {
            source: request_source(req)
          })
          json(res, 200, { cancelled: true, pairing_state: pairing_state_payload })
        else
          json(res, 409, { error: 'no_pending_activation', pairing_state: pairing_state_payload })
        end
      end

      @server.mount_proc('/api/v1/admin/monitoring') do |req, res|
        auth = authenticate(req)
        unless auth && can_manage_monitoring?(auth)
          json(res, 403, { error: 'forbidden' })
          next
        end

        case req.request_method
        when 'GET'
          audit_access(auth, req, 'admin.monitoring.get')
          json(res, 200, { monitoring_profile: @monitoring_profile })
        when 'PUT', 'PATCH'
          payload = parse_json(req)
          update_monitoring_profile(payload['monitoring_profile'] || payload)
          audit_event('admin.monitoring.updated', actor: auth['username'], details: { services: @monitoring_profile['services'].length, devices: @monitoring_profile['devices'].length, states: @monitoring_profile['states'].length, actions: @monitoring_profile['actions'].length })
          json(res, 200, { updated: true, monitoring_profile: @monitoring_profile })
        else
          json(res, 405, { error: 'method_not_allowed' })
        end
      end

      @server.mount_proc('/api/v1/admin/catalog') do |req, res|
        auth = authenticate(req)
        unless auth && can_manage_monitoring?(auth)
          json(res, 403, { error: 'forbidden' })
          next
        end

        audit_access(auth, req, 'admin.catalog')
        json(res, 200, build_catalog_payload)
      end

      @server.mount_proc('/api/v1/audit') do |req, res|
        auth = authenticate(req)
        unless auth
          json(res, 401, { error: 'unauthorized' })
          next
        end

        audit_access(auth, req, 'audit')
        json(res, 200, {
          retention_days: AUDIT_RETENTION_DAYS,
          events: filtered_audit_events_for(auth, limit: 500)
        })
      end

      @server.mount_proc('/api/v1/home/revoke-integrator') do |req, res|
        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        auth = authenticate(req)
        unless auth && auth['role'] == 'home_admin' && !auth['requires_password_change']
          json(res, 403, { error: 'forbidden' })
          next
        end

        revoke_integrator_access(actor: auth['username'])
        audit_event('integrator.access.revoked', actor: auth['username'], details: {
          warning: 'integrator access remains blocked until a new Blueprint config revision or reset flag is uploaded'
        })
        json(res, 200, {
          revoked: true,
          warning: 'Integrator access is revoked. A new Blueprint config revision or reset flag is required to restore integrator access.'
        })
      end

      @server.mount_proc('/api/v1/home/integrator-access') do |req, res|
        auth = authenticate(req)
        unless auth && auth['role'] == 'home_admin' && !auth['requires_password_change']
          json(res, 403, { error: 'forbidden' })
          next
        end

        if req.request_method == 'GET'
          json(res, 200, {
            enabled: @policy['integrator_access_temporarily_disabled'] ? false : true,
            temporarily_disabled: @policy['integrator_access_temporarily_disabled'] ? true : false,
            disabled_at: @policy['integrator_access_temporarily_disabled_at'],
            disabled_by: @policy['integrator_access_temporarily_disabled_by']
          })
          next
        end

        unless req.request_method == 'POST'
          json(res, 405, { error: 'method_not_allowed' })
          next
        end

        payload = parse_json(req)
        unless payload.key?('enabled')
          json(res, 400, { error: 'enabled_required' })
          next
        end

        enabled = payload['enabled'] ? true : false
        set_integrator_temporary_access(actor: auth['username'], enabled: enabled)
        if enabled
          audit_event('integrator.access.temporarily_enabled', actor: auth['username'], details: {})
          json(res, 200, {
            enabled: true,
            temporarily_disabled: false,
            message: 'Integrator access is enabled.'
          })
        else
          audit_event('integrator.access.temporarily_disabled', actor: auth['username'], details: {})
          json(res, 200, {
            enabled: false,
            temporarily_disabled: true,
            warning: 'Integrator access is temporarily disabled by the homeowner. Existing integrator sessions were closed.'
          })
        end
      end

      @server.mount_proc('/api/v1/admin/audit') do |req, res|
        auth = authenticate(req)
        unless auth && (auth['role'] == 'integrator' || auth['role'] == 'home_admin') && !auth['requires_password_change']
          json(res, 403, { error: 'forbidden' })
          next
        end

        audit_access(auth, req, 'admin.audit')
        json(res, 200, {
          retention_days: AUDIT_RETENTION_DAYS,
          events: filtered_audit_events_for(auth, limit: 500)
        })
      end
    end

    def parse_json(req)
      body = req.body.to_s
      return {} if body.empty?
      JSON.parse(body)
    rescue JSON::ParserError
      {}
    end

    def json(res, status, payload)
      res.status = status
      res['Content-Type'] = 'application/json'
      res.body = JSON.pretty_generate(payload)
    end

    def setup_logger(log_level)
      FileUtils.mkdir_p(@log_directory)
      @logger = Logger.new(File.join(@log_directory, 'savant_network_sentinel_clean_rubi_bridge_v4_3b1_pro.log'), 5, 1_048_576)
      @logger.level = {
        'DEBUG' => Logger::DEBUG,
        'INFO' => Logger::INFO,
        'WARN' => Logger::WARN,
        'ERROR' => Logger::ERROR
      }[log_level.to_s.upcase] || Logger::INFO
      @logger.formatter = proc { |severity, datetime, _progname, message| "#{datetime.utc.iso8601} #{severity} #{message}\n" }
    end

    def truthy?(value)
      %w[1 true yes on enabled https].include?(value.to_s.strip.downcase)
    end

    def transport_scheme
      @use_https ? 'https' : 'http'
    end

    def ensure_tls_material
      FileUtils.mkdir_p(File.dirname(@tls_cert_file))
      FileUtils.mkdir_p(File.dirname(@tls_key_file))

      if File.file?(@tls_cert_file) && File.file?(@tls_key_file)
        certificate = OpenSSL::X509::Certificate.new(File.read(@tls_cert_file))
        private_key = OpenSSL::PKey.read(File.read(@tls_key_file))
      else
        certificate, private_key = generate_self_signed_certificate
        File.write(@tls_cert_file, certificate.to_pem)
        File.write(@tls_key_file, private_key.to_pem)
        File.chmod(0o600, @tls_cert_file) rescue nil
        File.chmod(0o600, @tls_key_file) rescue nil
      end

      @tls_certificate = certificate
      @tls_fingerprint = OpenSSL::Digest::SHA256.hexdigest(certificate.to_der).upcase.scan(/../).join(':')
      [certificate, private_key]
    end

    def generate_self_signed_certificate
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = Random.rand(100_000..999_999)
      cert.subject = OpenSSL::X509::Name.parse("/CN=Sentinel Bridge #{@site_name}")
      cert.issuer = cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.now
      cert.not_after = Time.now + (3650 * 24 * 60 * 60)

      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extension_factory.subject_certificate = cert
      extension_factory.issuer_certificate = cert
      cert.add_extension(extension_factory.create_extension('basicConstraints', 'CA:FALSE', true))
      cert.add_extension(extension_factory.create_extension('keyUsage', 'digitalSignature,keyEncipherment', true))
      cert.add_extension(extension_factory.create_extension('extendedKeyUsage', 'serverAuth', false))
      cert.add_extension(extension_factory.create_extension('subjectKeyIdentifier', 'hash', false))
      cert.add_extension(extension_factory.create_extension('authorityKeyIdentifier', 'keyid:always', false))

      cert.sign(key, OpenSSL::Digest::SHA256.new)
      [cert, key]
    end

    def start_harvest_thread
      emit_harvest_status('idle', '')
      @harvest_thread = Thread.new do
        loop do
          harvest_statecenter
          prune_audit_log_if_needed
          sleep(@harvest_poll_seconds)
        end
      end
    rescue => e
      emit_harvest_status('error', "#{e.class}:#{e.message}")
    end

    def harvest_statecenter
      unless @sclibridge_path
        emit_harvest_status('error', 'sclibridge_not_found')
        return
      end

      resolved = resolve_harvest_state_list
      if resolved.empty?
        @mutex.synchronize { @harvested_statecenter = {} }
        emit_harvest_status('idle', 'no_resolved_state_paths')
        return
      end

      to_read = next_harvest_slice(resolved)
      return if to_read.empty?

      harvested = read_statecenter_values(to_read)

      @mutex.synchronize do
        @harvested_statecenter ||= {}
        harvested.each do |state_path, payload|
          previous = @harvested_statecenter[state_path]
          cache_key = "statecenter:#{state_path}"
          if previous.nil? || previous['value'] != payload['value'] || previous['error'] != payload['error']
            @state_cache[cache_key] = {
              'type' => 'statecenter',
              'payload' => [state_path, payload['value'].to_s],
              'at' => payload['at']
            }
          end
          @harvested_statecenter[state_path] = payload
        end
      end
      refresh_bridge_catalog_cache_if_needed
      emit_harvest_status('running', '')
    rescue => e
      emit_harvest_status('error', "#{e.class}:#{e.message}")
    end

    def harvested_statecenter
      @mutex.synchronize do
        @harvested_statecenter ? @harvested_statecenter.dup : {}
      end
    end

    def harvested_state_count
      @mutex.synchronize do
        @harvested_statecenter ? @harvested_statecenter.length : 0
      end
    end

    def resolved_harvest_state_count
      @mutex.synchronize { @resolved_harvest_state_list.length }
    end

    def host_runtime_payload(detailed:)
      cache_key = detailed ? :detailed : :summary
      ttl = detailed ? @host_runtime_detailed_ttl : @host_runtime_summary_ttl
      cached = @host_runtime_cache[cache_key]
      if cached && cached[:payload] && (Time.now - cached[:at]) < ttl
        return cached[:payload]
      end

      payload = collect_host_runtime_payload(detailed: detailed)
      @host_runtime_cache[cache_key] = { at: Time.now, payload: payload }
      payload
    rescue => e
      @logger.error("host_runtime_payload failed #{e.class}: #{e.message}")
      {
        generated_at: Time.now.utc.iso8601,
        error: "#{e.class}: #{e.message}"
      }
    end

    def emit_harvest_status(status, error)
      puts ['statecenter_harvest', status, harvested_state_count, @harvest_poll_seconds, error.to_s.gsub(',', ';')].join(',')
      STDOUT.flush
    rescue => e
      @logger.error("emit_harvest_status failed #{e.class}: #{e.message}")
    end

    def collect_host_runtime_payload(detailed:)
      summary = read_process_summary(limit: detailed ? 10 : 5)
      memory = read_memory_summary
      disk = read_disk_summary
      memory_free_percent = if memory[:used_percent].is_a?(Numeric)
                              (100.0 - memory[:used_percent].to_f).round(1)
                            else
                              nil
                            end
      {
        generated_at: Time.now.utc.iso8601,
        host_uid: detect_host_uid,
        host_id: detect_host_uid,
        os_version: detect_os_version,
        host_software_version: detect_host_software_version,
        active_config_filename: active_config_filename,
        internal_ip: detect_internal_ip,
        external_ip: detect_external_ip,
        uptime: detect_uptime,
        process_count: summary[:process_count],
        active_processes: summary[:active_processes],
        memory_total_bytes: memory[:total_bytes],
        memory_used_bytes: memory[:used_bytes],
        memory_free_bytes: memory[:free_bytes],
        memory_used_percent: memory[:used_percent],
        memory_free_percent: memory_free_percent,
        memory: {
          total_bytes: memory[:total_bytes],
          used_bytes: memory[:used_bytes],
          free_bytes: memory[:free_bytes],
          used_percent: memory[:used_percent],
          free_percent: memory_free_percent
        },
        disk_total_bytes: disk[:total_bytes],
        disk_used_bytes: disk[:used_bytes],
        disk_free_bytes: disk[:free_bytes],
        disk: {
          total_bytes: disk[:total_bytes],
          used_bytes: disk[:used_bytes],
          free_bytes: disk[:free_bytes]
        },
        top_snapshot: detailed ? read_top_snapshot : [],
        syslog_tail: detailed ? read_syslog_tail : []
      }
    end

    def detect_internal_ip
      candidates = []
      en0, en0_status = Open3.capture2e('ipconfig', 'getifaddr', 'en0')
      candidates << en0.to_s.strip if en0_status.success?
      en1, en1_status = Open3.capture2e('ipconfig', 'getifaddr', 'en1')
      candidates << en1.to_s.strip if en1_status.success?

      route, route_status = Open3.capture2e('route', '-n', 'get', 'default')
      if route_status.success?
        route.to_s.each_line do |line|
          next unless line.include?('interface:')
          iface = line.split(':', 2).last.to_s.strip
          next if iface.empty?
          ip, ip_status = Open3.capture2e('ipconfig', 'getifaddr', iface)
          candidates << ip.to_s.strip if ip_status.success?
        end
      end

      candidates.map!(&:strip)
      candidates.find { |ip| ip.match?(/\A\d{1,3}(?:\.\d{1,3}){3}\z/) }
    rescue => e
      @logger.debug("detect_internal_ip failed #{e.class}: #{e.message}")
      nil
    end

    def detect_uptime
      stdout, status = Open3.capture2e('uptime')
      return nil unless status.success?

      output = stdout.to_s.strip
      return nil if output.empty?
      output
    rescue => e
      @logger.debug("detect_uptime failed #{e.class}: #{e.message}")
      nil
    end

    def detect_os_version
      product_name, status_name = Open3.capture2e('sw_vers', '-productName')
      product_version, status_version = Open3.capture2e('sw_vers', '-productVersion')
      build_version, status_build = Open3.capture2e('sw_vers', '-buildVersion')
      return nil unless status_name.success? || status_version.success? || status_build.success?

      [product_name, product_version, build_version]
        .map { |value| value.to_s.strip }
        .reject(&:empty?)
        .join(' ')
        .strip
        .yield_self { |value| value.empty? ? nil : value }
    rescue => e
      @logger.debug("detect_os_version failed #{e.class}: #{e.message}")
      nil
    end

    def detect_host_uid
      host = Socket.gethostname.to_s.strip
      if host =~ /([A-Fa-f0-9]{12,24})/
        return Regexp.last_match(1).upcase
      end
      if host =~ /sav-([A-Za-z0-9\-]+)/i
        suffix = Regexp.last_match(1).gsub('-', '')
        if suffix =~ /([A-Fa-f0-9]{12,24})/
          return Regexp.last_match(1).upcase
        end
      end

      states = harvested_statecenter
      states.each do |path, payload|
        key = path.to_s
        if key =~ /(?:^|\.)([A-Fa-f0-9]{12,24})(?:\.|$)/
          candidate = Regexp.last_match(1).to_s.upcase
          return candidate if candidate.length >= 12
        end
        if key =~ /\.(?:Chassis|Host|Home)?UID$/i || key =~ /\.(?:UniqueID|UniqueId)$/i
          value = payload.is_a?(Hash) ? payload['value'] : nil
          extracted = value.to_s[/([A-Fa-f0-9]{12,24})/, 1].to_s.upcase
          return extracted unless extracted.empty?
        end
        next unless key.include?('.ChassisIPAddress') || key.include?('.IPAddress') || key.include?('.OSVersion') || key.include?('.SoftwareVersion')
        value = payload.is_a?(Hash) ? payload['value'] : nil
        next if value.to_s.strip.empty?
        segments = key.split('.')
        uid = segments.find { |segment| segment =~ /\A[A-Fa-f0-9]{12,24}\z/ }
        return uid.upcase if uid
      end
      nil
    rescue => e
      @logger.debug("detect_host_uid failed #{e.class}: #{e.message}")
      nil
    end

    def detect_host_software_version
      value, _error = read_statecenter_value('global.HostSoftwareVersion')
      trimmed = value.to_s.strip
      return trimmed unless trimmed.empty?

      value2, _error2 = read_statecenter_value('global.ResidenceSoftwareVersion')
      trimmed2 = value2.to_s.strip
      return trimmed2 unless trimmed2.empty?

      states = harvested_statecenter
      states.each do |path, payload|
        key = path.to_s
        next unless key.match?(/(?:HostSoftwareVersion|ResidenceSoftwareVersion|SoftwareVersion)$/i)
        value = payload.is_a?(Hash) ? payload['value'] : nil
        trimmed = value.to_s.strip
        next if trimmed.empty?
        lower = trimmed.downcase
        next if lower.include?('android') || lower.start_with?('ios') || lower.include?('firmware') || lower.include?('appversion')
        return trimmed
      end

      nil
    rescue => e
      @logger.debug("detect_host_software_version failed #{e.class}: #{e.message}")
      nil
    end

    def detect_active_config_from_states
      states = harvested_statecenter
      return '' unless states.is_a?(Hash) && !states.empty?

      preferred_keys = [
        'ProfileNamesAndDates',
        'FetchProfileProperties',
        'ActiveConfiguration',
        'ActiveConfig',
        'ConfigurationInfo',
        'Profiles'
      ]

      candidates = []
      states.each do |path, payload|
        key = path.to_s
        next unless preferred_keys.any? { |segment| key.include?(segment) }
        value = payload.is_a?(Hash) ? payload['value'] : payload
        parsed = extract_config_filename_from_text(value.to_s)
        candidates << parsed unless parsed.empty?
      end

      candidates.find { |item| !item.empty? }.to_s
    rescue => e
      @logger.debug("detect_active_config_from_states failed #{e.class}: #{e.message}")
      ''
    end

    def extract_config_filename_from_text(text)
      return '' if text.to_s.strip.empty?

      candidate = text.to_s.strip
      if candidate =~ /([A-Za-z0-9_ \-]+?\(\d{4}-\d{2}-\d{2}[_\-]\d{2}-\d{2}-\d{2}\))/
        return Regexp.last_match(1).strip
      end
      if candidate =~ /([A-Za-z0-9_ \-]+?_?\d+\s*\(\d{4}-\d{2}-\d{2}[_\-]\d{2}-\d{2}-\d{2}\))/
        return Regexp.last_match(1).strip
      end

      compact = candidate.gsub(/\s+/, ' ').strip
      return '' if compact.match?(/\Av\d+\z/i)
      return compact if compact.length >= 10 && compact.match?(/[A-Za-z]/)

      ''
    rescue
      ''
    end

    def detect_external_ip
      urls = [
        'https://api.ipify.org',
        'https://ifconfig.me/ip',
        'https://ipv4.icanhazip.com'
      ]

      urls.each do |url_string|
        uri = URI.parse(url_string)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.open_timeout = 2
        http.read_timeout = 2
        request = Net::HTTP::Get.new(uri.request_uri)
        response = http.request(request)
        next unless response.is_a?(Net::HTTPSuccess)

        body = response.body.to_s.strip
        return body if body =~ /\A\d{1,3}(?:\.\d{1,3}){3}\z/
      rescue => e
        @logger.debug("external ip lookup failed via #{url_string}: #{e.class}: #{e.message}")
        next
      end

      nil
    end

    def read_process_summary(limit:)
      stdout, status = Open3.capture2e('ps', '-axo', 'pid=,pcpu=,pmem=,comm=')
      return { process_count: 0, active_processes: [] } unless status.success?

      rows = stdout.to_s.lines.map(&:strip).reject(&:empty?).map do |line|
        parts = line.split(/\s+/, 4)
        next if parts.length < 4
        {
          'pid' => parts[0],
          'cpu' => parts[1],
          'mem' => parts[2],
          'command' => parts[3]
        }
      end.compact

      sorted = rows.sort_by { |row| -row['cpu'].to_f }
      {
        process_count: rows.length,
        active_processes: sorted.first(limit)
      }
    rescue => e
      @logger.error("read_process_summary failed #{e.class}: #{e.message}")
      { process_count: 0, active_processes: [] }
    end

    def read_top_snapshot
      stdout, status = Open3.capture2e('top', '-l', '1', '-o', 'cpu', '-stats', 'pid,command,cpu,mem,time', '-n', '10')
      return [] unless status.success?

      stdout.to_s.lines
            .map(&:rstrip)
            .reject(&:empty?)
            .first(18)
    rescue => e
      @logger.error("read_top_snapshot failed #{e.class}: #{e.message}")
      []
    end

    def read_memory_summary
      total_stdout, total_status = Open3.capture2e('sysctl', '-n', 'hw.memsize')
      return { total_bytes: nil, used_bytes: nil, free_bytes: nil, used_percent: nil } unless total_status.success?

      total_bytes = total_stdout.to_s.strip.to_i
      return { total_bytes: nil, used_bytes: nil, free_bytes: nil, used_percent: nil } if total_bytes <= 0

      vm_stdout, vm_status = Open3.capture2e('vm_stat')
      return { total_bytes: total_bytes, used_bytes: nil, free_bytes: nil, used_percent: nil } unless vm_status.success?

      page_size = vm_stdout[/page size of (\d+) bytes/, 1].to_i
      page_size = 4096 if page_size <= 0
      values = {}
      vm_stdout.each_line do |line|
        next unless line.include?(':')
        key, raw = line.split(':', 2)
        values[key.to_s.strip] = raw.to_s.gsub('.', '').strip.to_i
      end

      free_pages = values.fetch('Pages free', 0) + values.fetch('Pages speculative', 0)
      inactive_pages = values.fetch('Pages inactive', 0)
      active_pages = values.fetch('Pages active', 0)
      wired_pages = values.fetch('Pages wired down', 0)
      compressed_pages = values.fetch('Pages occupied by compressor', 0)

      available_pages = free_pages + inactive_pages
      used_pages = active_pages + wired_pages + compressed_pages

      free_bytes = available_pages * page_size
      used_bytes = total_bytes - free_bytes
      if used_bytes <= 0 && free_bytes <= 0
        return { total_bytes: total_bytes, used_bytes: nil, free_bytes: nil, used_percent: nil }
      end
      if used_bytes < 0
        used_bytes = 0
      end
      if total_bytes > 0 && used_bytes > total_bytes
        used_bytes = total_bytes
      end
      if total_bytes > 0 && free_bytes > total_bytes
        free_bytes = total_bytes
      end
      if used_pages <= 0 && used_bytes <= 0 && free_bytes > 0
        used_bytes = [total_bytes - free_bytes, 0].max
      end
      used_percent = total_bytes > 0 ? ((used_bytes.to_f / total_bytes.to_f) * 100.0).round(1) : nil

      {
        total_bytes: total_bytes,
        used_bytes: used_bytes,
        free_bytes: free_bytes,
        used_percent: used_percent
      }
    rescue => e
      @logger.error("read_memory_summary failed #{e.class}: #{e.message}")
      { total_bytes: nil, used_bytes: nil, free_bytes: nil, used_percent: nil }
    end

    def read_disk_summary
      stdout, status = Open3.capture2e('df', '-k', '/')
      return { total_bytes: nil, used_bytes: nil, free_bytes: nil } unless status.success?

      lines = stdout.to_s.lines.map(&:strip).reject(&:empty?)
      data = lines.last
      return { total_bytes: nil, used_bytes: nil, free_bytes: nil } unless data

      fields = data.split(/\s+/)
      return { total_bytes: nil, used_bytes: nil, free_bytes: nil } if fields.length < 4

      total_kb = fields[1].to_i
      used_kb = fields[2].to_i
      free_kb = fields[3].to_i
      {
        total_bytes: total_kb * 1024,
        used_bytes: used_kb * 1024,
        free_bytes: free_kb * 1024
      }
    rescue => e
      @logger.error("read_disk_summary failed #{e.class}: #{e.message}")
      { total_bytes: nil, used_bytes: nil, free_bytes: nil }
    end

    def read_syslog_tail
      candidates = [
        ['/usr/bin/tail', '-n', '10', '/var/log/system.log'],
        ['/usr/bin/log', 'show', '--style', 'syslog', '--last', '10m']
      ]

      candidates.each do |command|
        stdout, status = Open3.capture2e(*command)
        next unless status.success?

        lines = stdout.to_s.lines.map(&:rstrip).reject(&:empty?)
        next if lines.empty?
        return lines.last(10)
      rescue => e
        @logger.debug("read_syslog_tail failed via #{command.join(' ')}: #{e.class}: #{e.message}")
        next
      end

      []
    end

    def load_store
      @users = {}
      @monitoring_profile = default_monitoring_profile
      @policy = default_policy
      return unless File.exist?(@users_file)
      data = JSON.parse(File.read(@users_file))
      Array(data['users']).each do |item|
        @users[item['username']] = item
      end
      if data.is_a?(Hash) && data['monitoring_profile'].is_a?(Hash)
        @monitoring_profile = normalize_monitoring_profile(data['monitoring_profile'])
      end
      if data.is_a?(Hash) && data['policy'].is_a?(Hash)
        @policy = normalize_policy(data['policy'])
      end
    rescue => e
      @logger.error("load_store failed #{e.class}: #{e.message}")
      @users = {}
      @monitoring_profile = default_monitoring_profile
      @policy = default_policy
    end

    def persist_store
      FileUtils.mkdir_p(File.dirname(@users_file))
      File.write(@users_file, JSON.pretty_generate({
        'schema_version' => STORE_SCHEMA_VERSION,
        'site_name' => @site_name,
        'updated_at' => Time.now.utc.iso8601,
        'users' => @users.values.sort_by { |item| item['username'] },
        'monitoring_profile' => @monitoring_profile,
        'policy' => @policy
      }))
    end

    def reconcile_bootstrap_integrator
      if sentinel_reset_requested?
        reset_sentinel_configuration!
      else
        enforce_activation_expiry!
      end
      signature = bootstrap_signature
      if @users.empty? || @policy['bootstrap_signature'] != signature
        upsert_bootstrap_integrator
        @policy['integrator_access_revoked'] = false
        @policy['integrator_access_revoked_at'] = nil
        @policy['integrator_access_revoked_by'] = nil
        @policy['bootstrap_signature'] = signature
        @policy['sentinel_reset_flag'] = @integrator_reset_flag
        persist_store
      elsif !@users.key?(@bootstrap_username)
        upsert_bootstrap_integrator
      end
    end

    def bootstrap_signature
      [@bootstrap_username, @bootstrap_config_revision, @integrator_reset_flag].join('|')
    end

    def upsert_bootstrap_integrator
      create_user(
        username: @bootstrap_username,
        password: @bootstrap_password,
        role: 'integrator',
        enabled: true,
        permissions: default_permissions_for_role('integrator'),
        requires_password_change: true
      )
    end

    def sentinel_reset_requested?
      stored = @policy['sentinel_reset_flag'].to_s
      current = @integrator_reset_flag.to_s
      return false if stored.empty?
      stored != current
    end

    def reset_sentinel_configuration!
      @users = {}
      @monitoring_profile = default_monitoring_profile
      @policy = default_policy
      @policy['sentinel_reset_flag'] = @integrator_reset_flag
      @mutex.synchronize do
        @sessions.clear
      end
      audit_event('sentinel.reset.applied', actor: 'system', details: {
        reset_flag: @integrator_reset_flag
      })
    end

    def create_user(username:, password:, role:, enabled:, permissions: nil, requires_password_change: false)
      return :invalid if username.empty? || password.empty?
      role = normalize_role(role)
      return :singleton_role_taken unless singleton_role_available?(role, excluding_username: username)
      unless bootstrap_password_bypass_allowed?(username, requires_password_change) || password_policy_error(password, username: username).nil?
        return :weak_password
      end
      salt = SecureRandom.hex(16)
      @users[username] = {
        'username' => username,
        'role' => role,
        'enabled' => enabled,
        'email' => nil,
        'salt' => salt,
        'password_hash' => hash_password(password, salt, PASSWORD_ITERATIONS),
        'password_iterations' => PASSWORD_ITERATIONS,
        'permissions' => normalize_permissions(permissions || default_permissions_for_role(role)),
        'requires_password_change' => requires_password_change ? true : false,
        'acknowledged_monitoring_version' => 0,
        'role_acknowledged_at' => role == 'integrator' ? Time.now.utc.iso8601 : nil
      }
      persist_store
      emit_status('running', '') if @server_started
      :ok
    end

    def update_user(username:, password:, role:, enabled:, permissions:)
      user = @users[username]
      return false unless user
      normalized_role = role.nil? || role.to_s.empty? ? user['role'] : normalize_role(role)
      return :singleton_role_taken unless singleton_role_available?(normalized_role, excluding_username: username)

      if password && !password.to_s.empty?
        return :weak_password unless password_policy_error(password.to_s, username: username).nil?
        salt = SecureRandom.hex(16)
        user['salt'] = salt
        user['password_hash'] = hash_password(password.to_s, salt, PASSWORD_ITERATIONS)
        user['password_iterations'] = PASSWORD_ITERATIONS
        user['requires_password_change'] = false
      end
      user['role'] = normalized_role
      user['enabled'] = enabled unless enabled.nil?
      user['email'] = user['email'].to_s unless user['email'].nil?
      if permissions
        user['permissions'] = normalize_permissions(permissions)
      elsif role && !role.to_s.empty?
        user['permissions'] ||= normalize_permissions(default_permissions_for_role(normalized_role))
      end
      persist_store
      true
    end

    def change_password(username:, current_password:, new_password:, force_clear_bootstrap: false)
      user = @users[username.to_s]
      return false unless user
      return false unless password_matches?(user, current_password.to_s)
      return :weak_password unless password_policy_error(new_password, username: username).nil?

      salt = SecureRandom.hex(16)
      user['salt'] = salt
      user['password_hash'] = hash_password(new_password.to_s, salt, PASSWORD_ITERATIONS)
      user['password_iterations'] = PASSWORD_ITERATIONS
      user['requires_password_change'] = false if force_clear_bootstrap
      refresh_sessions_for_user(user['username'],
                                requires_password_change: false,
                                acknowledged_monitoring_version: user['acknowledged_monitoring_version'].to_i,
                                role_acknowledged_at: user['role_acknowledged_at'])
      persist_store
      :ok
    end

    def delete_user(username)
      user = @users[username.to_s]
      return false if username.to_s.empty? || username.to_s == @bootstrap_username
      return false if user && user['role'].to_s == 'home_admin'
      deleted = @users.delete(username.to_s)
      persist_store if deleted
      !deleted.nil?
    end

    def hash_password(password, salt, iterations = PASSWORD_ITERATIONS)
      OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iterations, 32, 'sha256').unpack1('H*')
    end

    def password_matches?(user, password)
      iterations = user['password_iterations'].to_i
      iterations = LEGACY_PASSWORD_ITERATIONS if iterations <= 0
      hash_password(password, user['salt'], iterations) == user['password_hash']
    end

    def login(username, password)
      enforce_activation_expiry!
      user = @users[username]
      return nil unless user && user['enabled']
      return nil if user['role'] == 'integrator' && @policy['integrator_access_revoked']
      return nil if user['role'] == 'integrator' && @policy['integrator_access_temporarily_disabled']
      if user['role'] == 'home_admin' && @policy['sentinel_reset_required']
        return nil
      end
      return nil unless password_matches?(user, password)

      token = SecureRandom.hex(24)
      session = @mutex.synchronize do
        @sessions[token] = {
          'token' => token,
          'username' => username,
          'role' => user['role'],
          'expires_at' => Time.now.to_i + 28_800,
          'permissions' => normalize_permissions(user['permissions'] || default_permissions_for_role(user['role'])),
          'requires_password_change' => user['requires_password_change'] ? true : false,
          'acknowledged_monitoring_version' => user['acknowledged_monitoring_version'].to_i,
          'role_acknowledged_at' => user['role_acknowledged_at']
        }
      end
      session
    end

    def authenticate(req)
      token = req.header['authorization'].to_a.first.to_s.sub(/^Bearer\s+/i, '')
      return nil if token.empty?
      @mutex.synchronize do
        session = @sessions[token]
        if session && session['expires_at'].to_i > Time.now.to_i
          session
        else
          @sessions.delete(token)
          nil
        end
      end
    end

    def active_sessions_count
      @mutex.synchronize do
        now = Time.now.to_i
        @sessions.delete_if { |_token, value| value['expires_at'].to_i <= now }
        @sessions.length
      end
    end

    def current_session(token)
      return nil if token.to_s.empty?
      @mutex.synchronize do
        session = @sessions[token.to_s]
        session && session['expires_at'].to_i > Time.now.to_i ? session : nil
      end
    end

    def sanitize_user(user)
      {
        username: user['username'],
        role: user['role'],
        enabled: user['enabled'],
        email: user['email'],
        password_iterations: user['password_iterations'].to_i.positive? ? user['password_iterations'].to_i : LEGACY_PASSWORD_ITERATIONS,
        requires_password_change: user['requires_password_change'] ? true : false,
        acknowledged_monitoring_version: user['acknowledged_monitoring_version'].to_i,
        role_acknowledged_at: user['role_acknowledged_at'],
        permissions: normalize_permissions(user['permissions'] || default_permissions_for_role(user['role']))
      }
    end

    def session_response(session)
      {
        token: session['token'],
        role: session['role'],
        username: session['username'],
        expires_in_seconds: [session['expires_at'].to_i - Time.now.to_i, 0].max,
        requires_password_change: session['requires_password_change'] ? true : false,
        requires_role_acknowledgement: requires_role_acknowledgement?(session),
        role_warning: role_warning_for(session['role']),
        requires_monitoring_acknowledgement: requires_monitoring_acknowledgement?(session),
        requires_integrator_authorization: session['role'] == 'home_admin' && !pairing_complete?,
        monitoring_profile_version: @policy['monitoring_profile_version'],
        integrator_access_revoked: @policy['integrator_access_revoked'] ? true : false,
        integrator_access_temporarily_disabled: @policy['integrator_access_temporarily_disabled'] ? true : false,
        pairing_state: pairing_state_payload,
        reset_flag_warning: reset_flag_warning,
        permissions: normalize_permissions(session['permissions'] || default_permissions_for_role(session['role'])),
        monitoring_profile: @monitoring_profile
      }
    end

    def default_supported_actions
      %w[site.config site.status site.discovery admin.users admin.monitoring admin.catalog audit tools.terminal tools.reboot tools.doorbell].freeze
    end

    def default_monitoring_profile
      {
        'services' => [],
        'devices' => [],
        'states' => [],
        'actions' => []
      }
    end

    def default_permissions_for_role(role)
      case normalize_role(role)
      when 'integrator'
        normalize_permissions({
          'services' => { 'mode' => 'all', 'allow' => [], 'deny' => [] },
          'devices' => { 'mode' => 'all', 'allow' => [], 'deny' => [] },
          'states' => { 'mode' => 'all', 'allow' => [], 'deny' => [] },
          'actions' => { 'mode' => 'all', 'allow' => [], 'deny' => [] }
        })
      when 'home_admin'
        normalize_permissions({
          'services' => { 'mode' => 'all', 'allow' => [], 'deny' => [] },
          'devices' => { 'mode' => 'all', 'allow' => [], 'deny' => [] },
          'states' => { 'mode' => 'all', 'allow' => [], 'deny' => [] },
          'actions' => { 'mode' => 'all', 'allow' => [], 'deny' => [] }
        })
      else
        normalize_permissions({
          'services' => permission_template('all', [], []),
          'devices' => permission_template('all', [], []),
          'states' => permission_template('all', [], []),
          'actions' => permission_template('selected', %w[site.config site.status], [])
        })
      end
    end

    def permission_template(mode, allow, deny)
      {
        'mode' => mode,
        'allow' => allow.dup,
        'deny' => deny.dup
      }
    end

    def normalize_permissions(raw)
      base = {
        'services' => permission_template('all', [], []),
        'devices' => permission_template('all', [], []),
        'states' => permission_template('all', [], []),
        'actions' => permission_template('selected', %w[site.config site.status], [])
      }
      input = raw.is_a?(Hash) ? raw : {}
      %w[services devices states actions].each do |dimension|
        section = input[dimension] || input[dimension.to_sym] || {}
        base[dimension] = {
          'mode' => %w[selected allow_list].include?(section['mode'].to_s) ? 'selected' : 'all',
          'allow' => Array(section['allow'] || section[:allow]).map(&:to_s).map(&:strip).reject(&:empty?).uniq,
          'deny' => Array(section['deny'] || section[:deny]).map(&:to_s).map(&:strip).reject(&:empty?).uniq
        }
      end
      base
    end

    def normalize_monitoring_profile(raw)
      input = raw.is_a?(Hash) ? raw : {}
      {
        'services' => Array(input['services'] || input[:services]).map(&:to_s).map(&:strip).reject(&:empty?).uniq,
        'devices' => Array(input['devices'] || input[:devices]).map(&:to_s).map(&:strip).reject(&:empty?).uniq,
        'states' => Array(input['states'] || input[:states]).map(&:to_s).map(&:strip).reject(&:empty?).uniq,
        'actions' => Array(input['actions'] || input[:actions]).map(&:to_s).map(&:strip).reject(&:empty?).uniq
      }
    end

    def update_monitoring_profile(raw)
      @monitoring_profile = normalize_monitoring_profile(raw)
      @policy['monitoring_profile_version'] = @policy['monitoring_profile_version'].to_i + 1
      persist_store
    end

    def effective_access_summary(session)
      {
        role: session['role'],
        monitoring_profile: @monitoring_profile,
        monitoring_profile_version: @policy['monitoring_profile_version'],
        requires_role_acknowledgement: requires_role_acknowledgement?(session),
        requires_monitoring_acknowledgement: requires_monitoring_acknowledgement?(session),
        pairing_complete: pairing_complete?,
        permissions: normalize_permissions(session['permissions'] || default_permissions_for_role(session['role']))
      }
    end

    def pairing_complete?
      enforce_activation_expiry!
      @policy['pairing_complete'] ? true : false
    end

    def pairing_state_payload
      pending = @policy['pending_home_admin_activation'].is_a?(Hash) ? @policy['pending_home_admin_activation'] : {}
      {
        pairing_complete: @policy['pairing_complete'] ? true : false,
        initialization_required: @policy['pairing_complete'] ? false : true,
        integrator_authorized_by_home_admin: @policy['integrator_authorized_by_home_admin'] ? true : false,
        home_admin_username: @policy['home_admin_username'],
        home_admin_email: @policy['home_admin_email'],
        home_admin_created: !@policy['home_admin_username'].to_s.empty?,
        integrator_access_temporarily_disabled: @policy['integrator_access_temporarily_disabled'] ? true : false,
        integrator_access_temporarily_disabled_at: @policy['integrator_access_temporarily_disabled_at'],
        integrator_access_temporarily_disabled_by: @policy['integrator_access_temporarily_disabled_by'],
        sentinel_reset_required: @policy['sentinel_reset_required'] ? true : false,
        sentinel_reset_reason: @policy['sentinel_reset_reason'],
        reset_flag_warning: reset_flag_warning,
        pending_activation: pending.empty? ? nil : {
          username: pending['username'],
          email: pending['email'],
          expires_at: pending['expires_at'],
          resend_count: pending['resend_count'].to_i,
          resend_remaining: [ACTIVATION_EMAIL_RESEND_LIMIT - pending['resend_count'].to_i, 0].max
        }
      }
    end

    def reset_flag_warning
      return nil if @integrator_reset_flag.to_s.strip.empty? || @integrator_reset_flag.to_s == '0'

      'Sentinel reset flag is currently active in Blueprint. Remove it from later unrelated config uploads or the installation may be reset again when the reset token changes.'
    end

    def build_catalog_payload
      states = (resolve_harvest_state_list + harvested_statecenter.keys).uniq.sort
      services = states.map { |path| state_catalog_entry(path)['service'] }.uniq.sort
      devices = states.map { |path| state_catalog_entry(path)['device'] }.uniq.sort
      {
        generated_at: Time.now.utc.iso8601,
        services: services,
        devices: devices,
        states: states,
        actions: @supported_actions,
        monitoring_profile: @monitoring_profile
      }
    end

    def bridge_catalog_payload
      now = Time.now
      if @bridge_catalog_cache && (now - @bridge_catalog_cache_at) < @bridge_catalog_ttl
        return @bridge_catalog_cache
      end
      refresh_bridge_catalog_cache_if_needed(force: true)
      @bridge_catalog_cache || { generated_at: Time.now.utc.iso8601, rooms: [], services: [], states_harvested: harvested_state_count }
    rescue => e
      @logger.warn("bridge_catalog_payload failed #{e.class}: #{e.message}")
      { generated_at: Time.now.utc.iso8601, error: "#{e.class}: #{e.message}", rooms: [], services: [] }
    end

    def refresh_bridge_catalog_cache_if_needed(force: false)
      now = Time.now
      return if !force && (now - @bridge_catalog_cache_at) < @bridge_catalog_ttl

      payload = build_bridge_catalog_payload
      @bridge_catalog_cache = payload
      @bridge_catalog_cache_at = now
      FileUtils.mkdir_p(File.dirname(@bridge_catalog_file))
      File.write(@bridge_catalog_file, JSON.pretty_generate(payload) + "\n")
    rescue => e
      @logger.warn("refresh_bridge_catalog_cache_if_needed failed #{e.class}: #{e.message}")
    end

    def build_bridge_catalog_payload
      states = harvested_statecenter
      rooms = Hash.new { |h, k| h[k] = { 'name' => k, 'state_count' => 0, 'services' => Hash.new(0) } }
      services = Hash.new(0)

      states.each_key do |path|
        entry = state_catalog_entry(path)
        service = entry['service'].to_s.strip
        service = 'other' if service.empty?
        services[service] += 1

        room = infer_room_name_from_state_path(path)
        next if room.to_s.strip.empty?

        rooms[room]['state_count'] += 1
        rooms[room]['services'][service] += 1
      end

      inferred_zone_names.each do |name|
        rooms[name] ||= { 'name' => name, 'state_count' => 0, 'services' => {} }
      end

      {
        generated_at: Time.now.utc.iso8601,
        active_config_filename: active_config_filename,
        host_uid: detect_host_uid,
        os_version: detect_os_version,
        host_software_version: detect_host_software_version,
        states_harvested: states.length,
        cameras: build_camera_catalog_entries(states),
        services: services.sort_by { |name, count| [-count.to_i, name.to_s] }.map { |name, count| { name: name, count: count.to_i } },
        rooms: rooms.values.map do |room|
          service_counts = room['services'].to_a.sort_by { |name, count| [-count.to_i, name.to_s] }.to_h
          {
            name: room['name'].to_s,
            state_count: room['state_count'].to_i,
            services: service_counts
          }
        end.sort_by { |room| [-room[:state_count].to_i, room[:name].to_s] }
      }
    end

    def build_camera_catalog_entries(states)
      cameras = {}
      merge_camera_catalog_from_states(cameras, states)
      merge_camera_catalog_from_config_files(cameras)
      cameras.values
             .map do |entry|
               {
                 name: entry[:name].to_s,
                 encoding: entry[:encoding].to_s.strip.empty? ? nil : entry[:encoding].to_s,
                 ip_address: entry[:ip_address].to_s.strip.empty? ? nil : entry[:ip_address].to_s,
                 stream_url: entry[:stream_url].to_s.strip.empty? ? nil : entry[:stream_url].to_s,
                 auth: entry[:auth].to_s.strip.empty? ? nil : entry[:auth].to_s
               }
             end
             .sort_by { |entry| entry[:name].to_s.downcase }
    rescue => e
      @logger.debug("build_camera_catalog_entries failed #{e.class}: #{e.message}")
      []
    end

    def merge_camera_catalog_from_states(cameras, states)
      states.each do |path, payload|
        next unless camera_signal_path?(path)

        camera_name = camera_name_from_path(path)
        key = camera_name.downcase
        cameras[key] ||= {
          name: camera_name,
          encoding: '',
          ip_address: '',
          stream_url: '',
          auth: ''
        }

        value = payload.is_a?(Hash) ? payload['value'].to_s : payload.to_s
        stream_url = first_stream_url(value) || first_stream_url(path.to_s)
        ip_address = first_ipv4(value) || first_ipv4(path.to_s)
        encoding = first_encoding_label(value) || first_encoding_label(path.to_s)
        auth = first_auth_label(value) || first_auth_label(path.to_s)

        cameras[key][:stream_url] = stream_url if cameras[key][:stream_url].to_s.strip.empty? && !stream_url.to_s.strip.empty?
        cameras[key][:ip_address] = ip_address if cameras[key][:ip_address].to_s.strip.empty? && !ip_address.to_s.strip.empty?
        cameras[key][:encoding] = encoding if cameras[key][:encoding].to_s.strip.empty? && !encoding.to_s.strip.empty?
        cameras[key][:auth] = auth if cameras[key][:auth].to_s.strip.empty? && !auth.to_s.strip.empty?
      end
    end

    def merge_camera_catalog_from_config_files(cameras)
      candidate_dirs = [running_rpm_config_directory, system_rpm_config_directory].map(&:to_s).reject(&:empty?).uniq
      candidate_dirs.each do |dir|
        next unless File.directory?(dir)

        glob_patterns = [
          '**/*camera*.xml',
          '**/*camera*.plist',
          '**/*camera*.json',
          '**/*video*.xml',
          '**/*video*.plist',
          '**/*video*.json',
          '**/*surveillance*.xml',
          '**/*surveillance*.plist',
          '**/*nvr*.xml',
          '**/*nvr*.plist',
          '**/*stream*.xml',
          '**/*stream*.plist',
          '**/*.sql',
          '**/*.sqlite',
          '**/*.db'
        ]
        files = glob_patterns.flat_map { |pattern| Dir.glob(File.join(dir, pattern), File::FNM_CASEFOLD) }.uniq

        files.each do |file_path|
          next unless File.file?(file_path)
          text = extract_searchable_text(file_path)
          next if text.to_s.strip.empty?

          stream_urls = text.scan(%r{(?:rtsp|rtsps|http|https)://[^\s"'<>]+}i).uniq
          next if stream_urls.empty?

          guessed_name = File.basename(file_path).sub(/\.[^.]+\z/, '').strip
          guessed_name = 'Camera' if guessed_name.empty?
          key = guessed_name.downcase
          cameras[key] ||= {
            name: guessed_name,
            encoding: '',
            ip_address: '',
            stream_url: '',
            auth: ''
          }

          stream = stream_urls.first.to_s
          cameras[key][:stream_url] = stream if cameras[key][:stream_url].to_s.strip.empty?
          ip_address = first_ipv4(stream) || first_ipv4(text)
          cameras[key][:ip_address] = ip_address if cameras[key][:ip_address].to_s.strip.empty? && !ip_address.to_s.strip.empty?
          encoding = first_encoding_label(text)
          cameras[key][:encoding] = encoding if cameras[key][:encoding].to_s.strip.empty? && !encoding.to_s.strip.empty?
          auth = first_auth_label(stream) || first_auth_label(text)
          cameras[key][:auth] = auth if cameras[key][:auth].to_s.strip.empty? && !auth.to_s.strip.empty?
        end
      end
    rescue => e
      @logger.debug("merge_camera_catalog_from_config_files failed #{e.class}: #{e.message}")
    end

    def extract_searchable_text(file_path)
      ext = File.extname(file_path).downcase
      if %w[.sql .json .xml .plist .txt .cfg .conf .ini].include?(ext)
        return File.read(file_path)
      end

      stdout, status = Open3.capture2e('strings', '-n', '6', file_path.to_s)
      return stdout.to_s if status.success?
      ''
    rescue => e
      @logger.debug("extract_searchable_text #{file_path} failed #{e.class}: #{e.message}")
      ''
    end

    def camera_signal_path?(path)
      normalized = path.to_s.downcase
      normalized.include?('camera') ||
        normalized.include?('stream') ||
        normalized.include?('surveillance') ||
        normalized.include?('nvr') ||
        normalized.include?('securitycamera') ||
        normalized.include?('activevideoservice')
    end

    def camera_name_from_path(path)
      parts = path.to_s.split('.').map(&:strip).reject(&:empty?)
      candidate = parts.find do |segment|
        normalized = segment.downcase
        normalized.include?('camera') || normalized.include?('nvr') || normalized.include?('surveillance')
      end
      candidate ||= parts.first || 'Camera'
      candidate.to_s
    end

    def first_stream_url(text)
      return nil if text.to_s.strip.empty?
      text.to_s[%r{(?:rtsp|rtsps|http|https)://[^\s"'<>]+}i]
    end

    def first_ipv4(text)
      return nil if text.to_s.strip.empty?
      text.to_s[/\b(?:\d{1,3}\.){3}\d{1,3}\b/]
    end

    def first_encoding_label(text)
      normalized = text.to_s.downcase
      return 'H.265 / HEVC' if normalized.include?('h.265') || normalized.include?('h265') || normalized.include?('hevc')
      return 'H.264 / AVC' if normalized.include?('h.264') || normalized.include?('h264') || normalized.include?('avc')
      return 'MJPEG' if normalized.include?('mjpeg') || normalized.include?('jpeg')
      return 'MPEG-4' if normalized.include?('mpeg4') || normalized.include?('mpeg-4')
      nil
    end

    def first_auth_label(text)
      value = text.to_s
      stream = first_stream_url(value)
      if stream
        begin
          uri = URI.parse(stream)
          if uri.user.to_s.strip != ''
            return uri.password.to_s.strip == '' ? uri.user.to_s : "#{uri.user}:••••"
          end
        rescue URI::InvalidURIError
          # ignore malformed URI
        end
      end
      normalized = value.downcase
      return 'Digest' if normalized.include?('digest')
      return 'Basic' if normalized.include?('basic')
      return 'Token' if normalized.include?('token')
      return 'Configured' if normalized.include?('username') || normalized.include?('password') || normalized.include?('auth')
      nil
    end

    def system_rpm_config_directory
      candidates = [
        '/Users/Shared/Savant/Library/Application Support/RacePointMedia/systemConfig.rpmConfig',
        '/Users/Shared/Savant/Library/ApplicationSupport/RacePointMedia/systemConfig.rpmConfig',
        '/home/RPM/GNUstep/Library/ApplicationSupport/RacePointMedia/systemConfig.rpmConfig',
        '/Users/RPM/GNUstep/Library/ApplicationSupport/RacePointMedia/systemConfig.rpmConfig',
        '/Users/RPM/Library/Application Support/RacePointMedia/systemConfig.rpmConfig',
        '/Users/RPM/Library/ApplicationSupport/RacePointMedia/systemConfig.rpmConfig'
      ]
      candidates.find do |path|
        File.exist?(File.join(path, 'serviceImplementation.xml')) ||
          File.directory?(File.join(path, 'componentProfiles'))
      end.to_s
    rescue => e
      @logger.debug("system_rpm_config_directory failed #{e.class}: #{e.message}")
      ''
    end

    def inferred_zone_names
      names = []
      rpm_dir = running_rpm_config_directory
      unless rpm_dir.to_s.empty?
        names.concat(zone_names_from_global_zone_text(File.join(rpm_dir, 'globalZoneOrganization.plist')))
        names.concat(zone_names_from_zone_info_text(File.join(rpm_dir, 'zoneInfo.plist')))
      end
      discover_user_zones.each { |zone| names << zone.to_s }
      names.map { |name| name.to_s.strip }.reject(&:empty?).uniq.sort
    rescue => e
      @logger.debug("inferred_zone_names failed #{e.class}: #{e.message}")
      []
    end

    def infer_room_name_from_state_path(path)
      parts = path.to_s.split('.').map(&:strip).reject(&:empty?)
      return '' if parts.empty?

      first = parts.first.to_s
      normalized = first.downcase.gsub(/[^a-z0-9]/, '')
      return '' if normalized.empty?
      return '' if %w[global genericcomponent generic_component racepointmedia system host bridge userconfig rpmconfig].include?(normalized)
      return '' if first.match?(/\A[A-Fa-f0-9]{12,24}\z/)
      return '' if first.match?(/\A[A-Fa-f0-9\-]{24,}\z/)

      first
    rescue
      ''
    end

    def harvested_statecenter_for(session)
      all = harvested_statecenter
      return {} unless pairing_complete?
      return all if session['role'] == 'integrator'

      filtered = {}
      all.each do |state_path, payload|
        filtered[state_path] = payload if state_visible_to_session?(session, state_path)
      end
      filtered
    end

    def state_visible_to_session?(session, state_path)
      entry = state_catalog_entry(state_path)
      monitored_state?(entry) &&
        allowed_by_permissions?(session, 'services', entry['service']) &&
        allowed_by_permissions?(session, 'devices', entry['device']) &&
        allowed_by_permissions?(session, 'states', entry['state'])
    end

    def action_allowed?(session, action_name)
      return false if session['requires_password_change']
      return false if requires_role_acknowledgement?(session)
      return false if requires_monitoring_acknowledgement?(session)
      return false if initialization_gate_applies?(action_name) && !pairing_complete?
      return true if session['role'] == 'integrator'
      monitored_action?(action_name) && allowed_by_permissions?(session, 'actions', action_name)
    end

    def initialization_gate_applies?(action_name)
      %w[site.config site.status site.discovery].include?(action_name.to_s)
    end

    def refresh_sessions_for_user(username, requires_password_change:, acknowledged_monitoring_version:, role_acknowledged_at:)
      @mutex.synchronize do
        @sessions.each_value do |session|
          next unless session['username'] == username.to_s
          session['requires_password_change'] = requires_password_change ? true : false
          session['acknowledged_monitoring_version'] = acknowledged_monitoring_version.to_i
          session['role_acknowledged_at'] = role_acknowledged_at
        end
      end
    end

    def bootstrap_password_bypass_allowed?(username, requires_password_change)
      requires_password_change && username.to_s == @bootstrap_username.to_s
    end

    def password_policy_error(password, username: nil)
      value = password.to_s
      return :too_short if value.length < 7
      return :too_long if value.length > 128
      return :matches_bootstrap_secret if value == @bootstrap_password
      return :contains_whitespace_only if value.strip.empty?

      normalized = value.downcase
      return :too_common if normalized.match?(/password|letmein|welcome|qwerty|admin|sentinel|savant|changeme|123456|654321|abcdef/i)
      return :repetitive if normalized.match?(/(.)\1{3,}/)
      return :sequential if normalized.include?('1234') || normalized.include?('abcd') || normalized.include?('qwerty')

      if username
        user_fragment = username.to_s.downcase.gsub(/[^a-z0-9]/, '')
        return :contains_username if user_fragment.length >= 3 && normalized.gsub(/[^a-z0-9]/, '').include?(user_fragment)
      end

      category_count = 0
      category_count += 1 if value.match?(/[a-z]/)
      category_count += 1 if value.match?(/[A-Z]/)
      category_count += 1 if value.match?(/[0-9]/)
      category_count += 1 if value.match?(/[^A-Za-z0-9]/)
      return :insufficient_complexity if category_count < 3

      nil
    end

    def password_policy_summary
      {
        min_length: 7,
        max_length: 128,
        required_character_classes: 3,
        character_classes: ['lowercase', 'uppercase', 'digit', 'symbol'],
        disallow_username: true,
        disallow_common_passwords: true,
        disallow_repetitive_or_sequential_patterns: true
      }
    end

    def monitored_state?(entry)
      profile = @monitoring_profile
      return true if profile['services'].empty? && profile['devices'].empty? && profile['states'].empty?

      profile['states'].include?(entry['state']) ||
        profile['devices'].include?(entry['device']) ||
        profile['services'].include?(entry['service'])
    end

    def monitored_action?(action_name)
      actions = @monitoring_profile['actions']
      actions.empty? || actions.include?(action_name)
    end

    def valid_email?(email)
      value = email.to_s.strip
      value.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
    end

    def activation_password
      alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*'
      Array.new(18) { alphabet[SecureRandom.random_number(alphabet.length)] }.join
    end

    def initiate_home_admin_activation(username:, email:)
      enforce_activation_expiry!
      return { status: :reset_required } if @policy['sentinel_reset_required']
      return { status: :already_exists } unless @policy['home_admin_username'].to_s.empty?
      return { status: :invalid_username } if username.to_s.strip.empty?
      return { status: :invalid_email } unless valid_email?(email)

      temp_password = activation_password
      created = create_user(
        username: username.to_s.strip,
        password: temp_password,
        role: 'home_admin',
        enabled: true,
        permissions: default_permissions_for_role('home_admin'),
        requires_password_change: true
      )
      return { status: created } unless created == :ok

      @users[username.to_s.strip]['email'] = email.to_s.strip
      expires_at = (Time.now.utc + ACTIVATION_PASSWORD_VALIDITY_SECONDS).iso8601
      @policy['home_admin_username'] = username.to_s.strip
      @policy['home_admin_email'] = email.to_s.strip
      @policy['integrator_authorized_by_home_admin'] = false
      @policy['pairing_complete'] = false
      @policy['pairing_completed_at'] = nil
      @policy['sentinel_reset_required'] = false
      @policy['sentinel_reset_reason'] = nil
      @policy['pending_home_admin_activation'] = {
        'username' => username.to_s.strip,
        'email' => email.to_s.strip,
        'expires_at' => expires_at,
        'resend_count' => 0
      }

      delivery = activation_delivery_payload(
        username: username.to_s.strip,
        email: email.to_s.strip,
        password: temp_password,
        expires_at: expires_at
      )

      if send_activation_email(username: username.to_s.strip, email: email.to_s.strip, password: temp_password, expires_at: expires_at)
        persist_store
        {
          status: :ok,
          activation_delivery: delivery,
          delivery_method: 'host_email'
        }
      else
        persist_store
        {
          status: :manual_delivery_required,
          activation_delivery: delivery,
          delivery_method: 'mail_app'
        }
      end
    end

    def resend_home_admin_activation(email: nil)
      enforce_activation_expiry!
      return { status: :reset_required } if @policy['sentinel_reset_required']
      pending = @policy['pending_home_admin_activation']
      return { status: :no_pending_activation } unless pending.is_a?(Hash)

      resend_count = pending['resend_count'].to_i
      if resend_count >= ACTIVATION_EMAIL_RESEND_LIMIT
        @policy['sentinel_reset_required'] = true
        @policy['sentinel_reset_reason'] = 'activation_resend_limit_reached'
        persist_store
        return { status: :reset_required }
      end

      username = pending['username'].to_s
      user = @users[username]
      return { status: :home_admin_missing } unless user
      target_email = email.to_s.strip.empty? ? pending['email'].to_s : email.to_s.strip
      return { status: :invalid_email } unless valid_email?(target_email)

      temp_password = activation_password
      salt = SecureRandom.hex(16)
      user['salt'] = salt
      user['password_hash'] = hash_password(temp_password, salt, PASSWORD_ITERATIONS)
      user['password_iterations'] = PASSWORD_ITERATIONS
      user['requires_password_change'] = true
      user['email'] = target_email
      expires_at = (Time.now.utc + ACTIVATION_PASSWORD_VALIDITY_SECONDS).iso8601
      pending['email'] = target_email
      @policy['home_admin_email'] = target_email
      pending['expires_at'] = expires_at
      pending['resend_count'] = resend_count + 1

      delivery = activation_delivery_payload(
        username: username,
        email: target_email,
        password: temp_password,
        expires_at: expires_at
      )

      if send_activation_email(username: username, email: target_email, password: temp_password, expires_at: expires_at)
        persist_store
        {
          status: :ok,
          email: target_email,
          resend_count: pending['resend_count'].to_i,
          activation_delivery: delivery,
          delivery_method: 'host_email'
        }
      else
        persist_store
        {
          status: :manual_delivery_required,
          email: target_email,
          resend_count: pending['resend_count'].to_i,
          activation_delivery: delivery,
          delivery_method: 'mail_app'
        }
      end
    end

    def cancel_home_admin_activation
      return false if @policy['pairing_complete']
      pending = @policy['pending_home_admin_activation']
      return false unless pending.is_a?(Hash)

      username = pending['username'].to_s
      @users.delete(username) if @users[username] && @users[username]['role'].to_s == 'home_admin'
      @policy['home_admin_username'] = nil
      @policy['home_admin_email'] = nil
      @policy['integrator_authorized_by_home_admin'] = false
      @policy['pairing_complete'] = false
      @policy['pairing_completed_at'] = nil
      @policy['pending_home_admin_activation'] = nil
      @policy['sentinel_reset_required'] = false
      @policy['sentinel_reset_reason'] = nil
      persist_store
      true
    end

    def authorize_integrator(actor:)
      @policy['integrator_authorized_by_home_admin'] = true
      @policy['pairing_complete'] = true
      @policy['pairing_completed_at'] = Time.now.utc.iso8601
      @policy['pending_home_admin_activation'] = nil
      persist_store
    end

    def enforce_activation_expiry!
      pending = @policy['pending_home_admin_activation']
      return unless pending.is_a?(Hash)
      expires_at = Time.parse(pending['expires_at'].to_s) rescue nil
      return unless expires_at && Time.now.utc > expires_at
      return if @policy['pairing_complete']

      @policy['sentinel_reset_required'] = true
      @policy['sentinel_reset_reason'] = 'activation_expired'
      persist_store
    end

    def send_activation_email(username:, email:, password:, expires_at:)
      hostname = Socket.gethostname rescue 'localhost'
      from_address = "sentinel@#{hostname}"
      body = <<~MAIL
        To: #{email}
        From: #{from_address}
        Subject: Sentinel Home Admin Activation

        Sentinel home activation has been created for #{username}.

        Temporary password: #{password}
        Valid until: #{expires_at}

        This password is valid for 5 minutes only and must be changed on first login.
      MAIL
      stdout, stderr, status = Open3.capture3('/usr/sbin/sendmail', '-t', stdin_data: body)
      @logger.warn("sendmail stderr: #{stderr}") unless stderr.to_s.strip.empty?
      status.success?
    rescue => e
      @logger.error("send_activation_email failed #{e.class}: #{e.message}")
      false
    end

    def send_user_temporary_password_email(username:, role:, email:, password:)
      hostname = Socket.gethostname rescue 'localhost'
      from_address = "sentinel@#{hostname}"
      body = <<~MAIL
        To: #{email}
        From: #{from_address}
        Subject: Sentinel Temporary Password

        Sentinel created temporary access for #{username} (role: #{role}).

        Temporary password: #{password}

        This password must be changed on first login.
      MAIL
      stdout, stderr, status = Open3.capture3('/usr/sbin/sendmail', '-t', stdin_data: body)
      @logger.warn("sendmail stderr: #{stderr}") unless stderr.to_s.strip.empty?
      status.success?
    rescue => e
      @logger.error("send_user_temporary_password_email failed #{e.class}: #{e.message}")
      false
    end

    def activation_delivery_payload(username:, email:, password:, expires_at:)
      hostname = Socket.gethostname rescue 'localhost'
      subject = 'Sentinel Home Admin Activation'
      body = <<~BODY
        Sentinel home activation has been created for #{username}.

        Temporary password: #{password}
        Valid until: #{expires_at}

        This password is valid for 5 minutes only and must be changed on first login.

        Sent from Sentinel on #{hostname}.
      BODY

      {
        method: 'mail_app',
        to: email,
        subject: subject,
        body: body
      }
    end

    def user_temporary_password_delivery_payload(username:, role:, email:, password:)
      hostname = Socket.gethostname rescue 'localhost'
      subject = 'Sentinel Temporary Password'
      body = <<~BODY
        Sentinel created temporary access for #{username} (role: #{role}).

        Temporary password: #{password}

        This password must be changed on first login.

        Sent from Sentinel on #{hostname}.
      BODY

      {
        method: 'mail_app',
        to: email.to_s.empty? ? nil : email,
        subject: subject,
        body: body
      }
    end

    def requires_monitoring_acknowledgement?(session)
      return false unless %w[integrator home_admin].include?(session['role'].to_s)
      session['acknowledged_monitoring_version'].to_i < @policy['monitoring_profile_version'].to_i
    end

    def requires_role_acknowledgement?(session)
      %w[home_admin home_user].include?(session['role'].to_s) && session['role_acknowledged_at'].to_s.strip.empty?
    end

    def role_warning_for(role)
      case role.to_s
      when 'home_admin'
        'You are accepting the home admin role for this Sentinel installation. This role gives owner-level oversight of monitoring and user access for the home. Proceed only if you are the intended owner-authorized home administrator.'
      when 'home_user'
        'You are accepting the home user role for this Sentinel installation. If you are the actual home owner, contact your integrator immediately before proceeding, because the owner should not be left only with home-user access.'
      else
        nil
      end
    end

    def acknowledge_role(username)
      user = @users[username.to_s]
      return false unless user
      user['role_acknowledged_at'] = Time.now.utc.iso8601
      persist_store
      true
    end

    def acknowledge_monitoring(username)
      user = @users[username.to_s]
      return false unless user
      user['acknowledged_monitoring_version'] = @policy['monitoring_profile_version'].to_i
      persist_store
      true
    end

    def allowed_by_permissions?(session, dimension, value)
      permissions = normalize_permissions(session['permissions'] || default_permissions_for_role(session['role']))
      section = permissions[dimension] || {}
      allow = Array(section['allow'])
      deny = Array(section['deny'])
      return false if deny.include?(value)
      return true unless section['mode'] == 'selected'

      allow.include?(value)
    end

    def state_catalog_entry(state_path)
      path = state_path.to_s.strip
      device, leaf = path.split('.', 2)
      leaf ||= path
      {
        'state' => path,
        'device' => device.to_s.empty? ? 'global' : device.to_s,
        'service' => classify_service(path, leaf)
      }
    end

    def classify_service(path, leaf)
      return 'bridge' if path.start_with?('global.') || path.start_with?('Generic_component.')
      return 'security' if leaf =~ /(Security|Alarm|Camera|Texecom|ZoneSummary|SecurityStatus|NumberOfSecurityFaults)/i
      return 'access' if leaf =~ /(Door|Lock|MagLock|Gate|Entry)/i
      return 'garage' if leaf =~ /(Garage)/i
      return 'audio_video' if leaf =~ /(AVB|AVoIP|SVC_AV|Audio|Video|Stream|Source|Layout)/i
      return 'hvac' if leaf =~ /(Thermostat|Temperature|SetPoint|HVAC|Heat|Cool|Fan)/i
      return 'shades' if leaf =~ /(Shade|Blind|Position|Motor)/i
      return 'lighting' if leaf =~ /(Relay|Dimmer|Lighting|Output|ConvertLevel)/i
      'other'
    end

    def audit_access(session, req, action_name)
      audit_event('access', actor: session['username'], details: {
        action: action_name,
        method: req.request_method,
        path: req.path,
        source: request_source(req)
      })
    end

    def audit_event(event_type, actor:, details:)
      entry = {
        'at' => Time.now.utc.iso8601,
        'type' => event_type,
        'actor' => actor.to_s,
        'details' => details
      }
      FileUtils.mkdir_p(File.dirname(@audit_log_file))
      File.open(@audit_log_file, 'a') { |file| file.puts(JSON.generate(entry)) }
    rescue => e
      @logger.error("audit_event failed #{e.class}: #{e.message}")
    end

    def read_audit_events(limit:)
      return [] unless File.exist?(@audit_log_file)

      events = []
      File.foreach(@audit_log_file) do |line|
        next if line.to_s.strip.empty?
        events << JSON.parse(line)
      rescue JSON::ParserError
        next
      end
      events.last(limit)
    rescue => e
      @logger.error("read_audit_events failed #{e.class}: #{e.message}")
      []
    end

    def prune_audit_log_if_needed(force: false)
      now = Time.now
      return if !force && (now - @last_audit_prune_at) < 43_200

      @last_audit_prune_at = now
      return unless File.exist?(@audit_log_file)

      cutoff = now - (AUDIT_RETENTION_DAYS * 86_400)
      kept = []
      File.foreach(@audit_log_file) do |line|
        next if line.to_s.strip.empty?
        entry = JSON.parse(line)
        at = Time.parse(entry['at'].to_s) rescue nil
        kept << JSON.generate(entry) if at && at >= cutoff
      rescue JSON::ParserError
        next
      end
      File.write(@audit_log_file, kept.join("\n") + (kept.empty? ? '' : "\n"))
    rescue => e
      @logger.error("prune_audit_log_if_needed failed #{e.class}: #{e.message}")
    end

    def request_source(req)
      req.remote_ip.to_s
    rescue
      ''
    end

    def default_policy
      {
        'bootstrap_signature' => nil,
        'sentinel_reset_flag' => @integrator_reset_flag,
        'monitoring_profile_version' => 1,
        'integrator_access_revoked' => false,
        'integrator_access_revoked_at' => nil,
        'integrator_access_revoked_by' => nil,
        'integrator_access_temporarily_disabled' => false,
        'integrator_access_temporarily_disabled_at' => nil,
        'integrator_access_temporarily_disabled_by' => nil,
        'home_admin_username' => nil,
        'home_admin_email' => nil,
        'integrator_authorized_by_home_admin' => false,
        'pairing_complete' => false,
        'pairing_completed_at' => nil,
        'pending_home_admin_activation' => nil,
        'sentinel_reset_required' => false,
        'sentinel_reset_reason' => nil
      }
    end

    def normalize_policy(raw)
      policy = default_policy
      input = raw.is_a?(Hash) ? raw : {}
      policy['bootstrap_signature'] = input['bootstrap_signature'].to_s unless input['bootstrap_signature'].nil?
      policy['sentinel_reset_flag'] = input['sentinel_reset_flag'].to_s unless input['sentinel_reset_flag'].nil?
      policy['monitoring_profile_version'] = [input['monitoring_profile_version'].to_i, 1].max
      policy['integrator_access_revoked'] = input['integrator_access_revoked'] ? true : false
      policy['integrator_access_revoked_at'] = input['integrator_access_revoked_at']
      policy['integrator_access_revoked_by'] = input['integrator_access_revoked_by']
      policy['integrator_access_temporarily_disabled'] = input['integrator_access_temporarily_disabled'] ? true : false
      policy['integrator_access_temporarily_disabled_at'] = input['integrator_access_temporarily_disabled_at']
      policy['integrator_access_temporarily_disabled_by'] = input['integrator_access_temporarily_disabled_by']
      policy['home_admin_username'] = input['home_admin_username']
      policy['home_admin_email'] = input['home_admin_email']
      policy['integrator_authorized_by_home_admin'] = input['integrator_authorized_by_home_admin'] ? true : false
      policy['pairing_complete'] = input['pairing_complete'] ? true : false
      policy['pairing_completed_at'] = input['pairing_completed_at']
      policy['pending_home_admin_activation'] = input['pending_home_admin_activation'].is_a?(Hash) ? input['pending_home_admin_activation'] : nil
      policy['sentinel_reset_required'] = input['sentinel_reset_required'] ? true : false
      policy['sentinel_reset_reason'] = input['sentinel_reset_reason']
      policy
    end

    def normalize_role(raw)
      role = raw.to_s.strip.downcase
      return 'integrator' if role == 'integrator'
      return 'home_admin' if role == 'home_admin'
      'home_user'
    end

    def singleton_role_available?(role, excluding_username:)
      normalized_role = normalize_role(role)
      return true unless %w[integrator home_admin].include?(normalized_role)

      @users.each_value do |user|
        next if user['username'].to_s == excluding_username.to_s
        return false if user['role'].to_s == normalized_role
      end
      true
    end

    def can_access_user_management?(session)
      return false if session['requires_password_change']
      return false if requires_monitoring_acknowledgement?(session)
      %w[integrator home_admin].include?(session['role'].to_s)
    end

    def can_manage_monitoring?(session)
      return false if session['requires_password_change']
      return false if requires_monitoring_acknowledgement?(session)
      %w[integrator home_admin].include?(session['role'].to_s)
    end

    def can_access_host_tools?(session)
      return false if session['requires_password_change']
      return false if requires_role_acknowledgement?(session)
      return false if requires_monitoring_acknowledgement?(session)
      return false unless pairing_complete?
      %w[integrator home_admin].include?(session['role'].to_s)
    end

    def purge_expired_terminal_sessions!
      cutoff = Time.now.utc - @terminal_session_timeout_seconds
      @mutex.synchronize do
        @terminal_sessions.delete_if do |_id, entry|
          last_seen = Time.parse(entry['last_seen_at'].to_s) rescue nil
          !last_seen || last_seen < cutoff
        end
      end
    end

    def touch_terminal_session(session_id:, actor:)
      purge_expired_terminal_sessions!
      @mutex.synchronize do
        entry = @terminal_sessions[session_id.to_s]
        return nil unless entry
        return nil unless entry['username'].to_s == actor.to_s

        entry['last_seen_at'] = Time.now.utc.iso8601
        entry
      end
    end

    def remove_terminal_session(session_id:, actor:)
      @mutex.synchronize do
        entry = @terminal_sessions[session_id.to_s]
        return false unless entry
        return false unless entry['username'].to_s == actor.to_s

        @terminal_sessions.delete(session_id.to_s)
        true
      end
    end

    def terminal_command_allowed?(command)
      value = command.to_s.strip
      return false if value.empty?

      blocked_patterns = [
        /(^|[\s;&|])(rm|mv|dd|mkfs|diskutil|fdisk|shutdown|reboot|halt|poweroff)\b/i,
        /\bchmod\s+777\b/i,
        /\bcurl\b.*\|\s*(bash|sh)\b/i,
        /(^|[\s;&|])sudo\b/i
      ]
      return false if blocked_patterns.any? { |pattern| value.match?(pattern) }

      allowed_prefixes = %w[
        ls pwd cd cat head tail grep rg find wc awk sed cut sort uniq tr
        date uptime whoami id ps top htop df du free uname sw_vers
        sclibridge ruby irb echo printf
      ]
      prefix = value.split(/\s+/).first.to_s
      allowed_prefixes.include?(prefix)
    end

    def execute_terminal_command(command:, sudo_password:, actor:)
      started_at = Time.now.utc.iso8601
      command_text = command.to_s.strip
      timed_out = false
      stdout = ''
      status = nil

      Timeout.timeout(20) do
        if sudo_password.to_s.strip.empty?
          stdout, status = Open3.capture2e('sh', '-lc', command_text)
        else
          sudo_payload = "printf '%s\\n' \"$SENTINEL_SUDO_PASSWORD\" | sudo -S -p '' sh -lc #{Shellwords.escape(command_text)}"
          env = { 'SENTINEL_SUDO_PASSWORD' => sudo_password.to_s }
          stdout, status = Open3.capture2e(env, 'sh', '-lc', sudo_payload)
        end
      end

      {
        command: command_text,
        output: stdout.to_s,
        exit_code: status&.exitstatus || (status&.success? ? 0 : 1),
        ok: status&.success? ? true : false,
        timed_out: timed_out,
        at: started_at,
        actor: actor.to_s
      }
    rescue Timeout::Error
      timed_out = true
      {
        command: command_text,
        output: 'terminal_execution_timed_out',
        exit_code: 124,
        ok: false,
        timed_out: timed_out,
        at: started_at,
        actor: actor.to_s
      }
    rescue => e
      {
        command: command_text,
        output: "#{e.class}:#{e.message}",
        exit_code: 1,
        ok: false,
        timed_out: timed_out,
        at: started_at,
        actor: actor.to_s
      }
    end

    def request_host_reboot(mode:, sudo_password:, actor:)
      normalized_mode = %w[soft hard].include?(mode.to_s) ? mode.to_s : 'soft'
      command = if normalized_mode == 'hard'
                  '/sbin/shutdown -r now'
                else
                  if @sclibridge_path
                    "#{@sclibridge_path} writestate global.SentinelSoftReboot 1"
                  else
                    '/sbin/shutdown -r +1'
                  end
                end

      sudo_payload = "sleep 2; printf '%s\\n' \"$SENTINEL_SUDO_PASSWORD\" | sudo -S -p '' sh -lc #{Shellwords.escape(command)}"
      pid = Process.spawn({ 'SENTINEL_SUDO_PASSWORD' => sudo_password.to_s }, 'sh', '-lc', sudo_payload, [:out, :err] => '/dev/null')
      Process.detach(pid)

      {
        ok: true,
        queued: true,
        mode: normalized_mode,
        method: command,
        warning: 'Host reboot was requested. Active sessions will disconnect.'
      }
    rescue => e
      {
        ok: false,
        error: 'reboot_request_failed',
        detail: "#{e.class}:#{e.message}"
      }
    end

    def doorbell_status_payload
      discovery = discover_doorbell_reference_data
      reference_audio = reference_doorbell_audio_spec(discovery)
      sample_sounds = ensure_builtin_doorbell_samples(reference_audio)
      {
        generated_at: Time.now.utc.iso8601,
        current_reference: discovery[:current_reference],
        references_detected: discovery[:references],
        requires_sudo_for_patch: discovery[:requires_sudo_for_patch] ? true : false,
        custom_audio_directory: doorbell_custom_directory,
        reference_audio: reference_audio,
        sample_sounds: sample_sounds,
        guidance: 'Custom doorbell WAV files must match the exact codec, sample rate, channel count, bit depth, and frame duration of the active Savant doorbell reference file.'
      }
    rescue => e
      {
        generated_at: Time.now.utc.iso8601,
        error: 'doorbell_status_unavailable',
        detail: "#{e.class}:#{e.message}",
        references_detected: [],
        sample_sounds: []
      }
    end

    def handle_custom_doorbell_upload(file_name:, wav_base64:, sudo_password:, actor:, auto_apply:)
      payload = wav_base64.to_s.strip
      return { ok: false, http_status: 400, error: 'missing_wav_payload' } if payload.empty?

      data = Base64.strict_decode64(payload)
      return { ok: false, http_status: 413, error: 'doorbell_file_too_large', max_bytes: 5_000_000 } if data.bytesize > 5_000_000

      uploaded_audio = wav_metadata_from_data(data)
      return { ok: false, http_status: 400, error: 'invalid_wav_file' } unless uploaded_audio

      reference = reference_doorbell_audio_spec(discover_doorbell_reference_data)
      mismatches = doorbell_audio_compatibility_errors(expected: reference, actual: uploaded_audio)
      unless mismatches.empty?
        return {
          ok: false,
          http_status: 400,
          error: 'doorbell_audio_mismatch',
          mismatches: mismatches,
          expected_reference_audio: reference,
          uploaded_audio: uploaded_audio
        }
      end

      safe_name = sanitize_doorbell_file_name(file_name)
      stamp = Time.now.utc.strftime('%Y%m%d_%H%M%S')
      target_path = File.join(doorbell_custom_directory, "#{stamp}_#{safe_name}")
      FileUtils.mkdir_p(doorbell_custom_directory)
      File.binwrite(target_path, data)
      File.chmod(0o644, target_path) rescue nil

      result = {
        ok: true,
        uploaded_file_name: safe_name,
        uploaded_file_path: target_path,
        uploaded_audio: uploaded_audio,
        reference_audio: reference,
        applied: false
      }
      return result unless auto_apply

      apply_result = apply_doorbell_audio_reference(
        audio_file_path: target_path,
        sudo_password: sudo_password,
        actor: actor
      )
      result.merge(apply_result).merge(applied: apply_result[:ok] ? true : false)
    rescue ArgumentError
      { ok: false, http_status: 400, error: 'invalid_base64_payload' }
    rescue => e
      {
        ok: false,
        http_status: 500,
        error: 'doorbell_upload_failed',
        detail: "#{e.class}:#{e.message}"
      }
    end

    def handle_builtin_doorbell_apply(sample_id:, sudo_password:, actor:)
      reference = reference_doorbell_audio_spec(discover_doorbell_reference_data)
      samples = ensure_builtin_doorbell_samples(reference)
      sample = samples.find { |entry| entry[:id].to_s == sample_id.to_s }
      return { ok: false, http_status: 404, error: 'sample_not_found' } unless sample
      return { ok: false, http_status: 409, error: 'sample_unavailable', sample: sample } unless sample[:available]

      apply_result = apply_doorbell_audio_reference(
        audio_file_path: sample[:file].to_s,
        sudo_password: sudo_password,
        actor: actor
      )
      apply_result.merge(
        sample_id: sample[:id],
        sample_name: sample[:name],
        sample_category: sample[:category]
      )
    end

    def handle_builtin_doorbell_preview(sample_id:)
      reference = reference_doorbell_audio_spec(discover_doorbell_reference_data)
      samples = ensure_builtin_doorbell_samples(reference)
      sample = samples.find { |entry| entry[:id].to_s == sample_id.to_s.strip }
      return { ok: false, http_status: 404, error: 'sample_not_found' } unless sample

      file_path = sample[:file].to_s
      return { ok: false, http_status: 404, error: 'sample_file_missing' } unless File.file?(file_path)

      bytes = File.binread(file_path)
      {
        ok: true,
        sample_name: sample[:name].to_s,
        file_name: "#{sample[:id]}.wav",
        content_type: 'audio/wav',
        bytes: bytes
      }
    rescue => e
      {
        ok: false,
        http_status: 500,
        error: 'sample_preview_exception',
        message: e.message
      }
    end

    def apply_doorbell_audio_reference(audio_file_path:, sudo_password:, actor:)
      target_path = File.expand_path(audio_file_path.to_s)
      return { ok: false, http_status: 404, error: 'doorbell_audio_file_missing' } unless File.file?(target_path)

      discovery = discover_doorbell_reference_data
      references = discovery[:references]
      return { ok: false, http_status: 404, error: 'doorbell_reference_not_found' } if references.empty?

      replacement_token = afplay_path_token(target_path)
      grouped = Hash.new { |memo, key| memo[key] = [] }
      references.each do |entry|
        file = entry[:file].to_s
        token = entry[:token].to_s
        next if file.empty? || token.empty?
        grouped[file] << token
      end

      updates = []
      grouped.each do |file_path, tokens|
        next unless File.file?(file_path)
        original = File.binread(file_path)
        updated = replace_doorbell_reference_tokens(
          content: original,
          tokens: tokens.uniq,
          replacement_token: replacement_token
        )
        next if updated == original
        updates << {
          path: file_path,
          original: original,
          updated: updated
        }
      end

      return { ok: false, http_status: 409, error: 'doorbell_reference_replace_noop' } if updates.empty?

      requires_sudo = updates.any? { |entry| !File.writable?(entry[:path]) }
      if requires_sudo && sudo_password.to_s.strip.empty?
        return {
          ok: false,
          http_status: 400,
          error: 'sudo_password_required',
          requires_sudo_for_patch: true,
          files_requiring_sudo: updates.map { |entry| entry[:path] }.uniq
        }
      end

      backup_root = File.join(doorbell_assets_root, 'backups', Time.now.utc.strftime('%Y%m%d_%H%M%S'))
      FileUtils.mkdir_p(backup_root)

      updated_files = []
      updates.each do |entry|
        backup_name = entry[:path].gsub(/[\/\\]/, '__')
        backup_file = File.join(backup_root, backup_name)
        File.binwrite(backup_file, entry[:original])

        written = write_content_with_optional_sudo(
          path: entry[:path],
          content: entry[:updated],
          sudo_password: sudo_password
        )
        unless written
          return {
            ok: false,
            http_status: 500,
            error: 'doorbell_reference_update_failed',
            file: entry[:path]
          }
        end
        updated_files << entry[:path]
      end

      reload = attempt_doorbell_service_reload
      {
        ok: true,
        replaced_references: updated_files.length,
        updated_files: updated_files,
        applied_audio_path: target_path,
        applied_audio_token: replacement_token,
        requires_sudo_for_patch: requires_sudo,
        reload_attempted: reload[:attempted],
        reload_success: reload[:ok],
        reload_command: reload[:command],
        soft_reboot_recommended: reload[:ok] ? false : true,
        warning: reload[:ok] ? 'Doorbell reference updated and a live reload was requested.' : 'Doorbell reference updated. A soft reboot is recommended so all services reload the new audio file.'
      }
    rescue => e
      {
        ok: false,
        http_status: 500,
        error: 'doorbell_reference_update_exception',
        detail: "#{e.class}:#{e.message}"
      }
    end

    def discover_doorbell_reference_data
      references = []
      doorbell_reference_scan_files.each do |file_path|
        next unless File.file?(file_path)
        references.concat(extract_doorbell_references_from_file(file_path))
      end

      if references.empty?
        known_default_doorbell_reference_candidates.each do |candidate|
          references << {
            file: '',
            token: candidate,
            resolved_path: candidate,
            exists: File.file?(candidate)
          }
        end
      end

      deduped = {}
      references.each do |entry|
        key = [entry[:file].to_s, entry[:token].to_s, entry[:resolved_path].to_s].join('|')
        deduped[key] = entry
      end
      list = deduped.values
      current = list.find { |entry| entry[:exists] } || list.first
      requires_sudo = list.any? { |entry| !entry[:file].to_s.empty? && File.file?(entry[:file]) && !File.writable?(entry[:file]) }

      {
        references: list,
        current_reference: current,
        requires_sudo_for_patch: requires_sudo
      }
    rescue => e
      @logger.warn("discover_doorbell_reference_data failed #{e.class}: #{e.message}")
      {
        references: [],
        current_reference: nil,
        requires_sudo_for_patch: false
      }
    end

    def doorbell_reference_scan_files
      files = []
      rpm_dir = running_rpm_config_directory
      unless rpm_dir.to_s.empty?
        files << File.join(rpm_dir, 'serviceImplementation.xml')
        files << File.join(rpm_dir, 'serviceImplementation-serviceDefinitionOnly.xml')
        files.concat(Dir.glob(File.join(rpm_dir, 'workflows', '**', '*.wflow')))
        files.concat(Dir.glob(File.join(rpm_dir, '**', 'entryConfig.plist')))
      end
      files.select { |path| File.file?(path) }.uniq
    rescue => e
      @logger.warn("doorbell_reference_scan_files failed #{e.class}: #{e.message}")
      []
    end

    def extract_doorbell_references_from_file(file_path)
      refs = []
      File.open(file_path, 'rb') do |io|
        io.each_line do |raw_line|
          line = raw_line.to_s.force_encoding('UTF-8').scrub
          next unless line.downcase.include?('.wav')
          next unless line.downcase.match?(/doorbell|chime|intercom|audiointerrupt|audio_interrupt|afplay/)

          extract_wav_tokens_from_line(line).each do |token|
            resolved = expand_doorbell_reference_path(token, base_dir: File.dirname(file_path))
            refs << {
              file: file_path,
              token: token,
              resolved_path: resolved,
              exists: File.file?(resolved)
            }
          end
        end
      end
      refs
    rescue => e
      @logger.debug("extract_doorbell_references_from_file failed #{file_path} #{e.class}: #{e.message}")
      []
    end

    def extract_wav_tokens_from_line(line)
      tokens = []
      line.to_s.scan(/["']([^"']+?\.wav)["']/i) do |match|
        tokens << match.first.to_s.strip
      end
      line.to_s.scan(/(?:afplay|play)\s+([^<>"'\r\n]+?\.wav)/i) do |match|
        tokens << match.first.to_s.strip
      end
      tokens.map(&:strip).reject(&:empty?).uniq
    end

    def expand_doorbell_reference_path(token, base_dir:)
      value = token.to_s.strip
      value = value.sub(/\A(?:afplay|play)\s+/i, '')
      unescaped = value.gsub('\\ ', ' ')
      if unescaped.start_with?('~/')
        File.join(bridge_user_home_directory, unescaped.sub(/\A~\//, ''))
      elsif unescaped.start_with?('/')
        unescaped
      else
        File.expand_path(unescaped, base_dir.to_s)
      end
    end

    def bridge_user_home_directory
      candidates = [
        ENV['HOME'].to_s,
        '/Users/RPM',
        '/home/RPM'
      ].map(&:to_s).reject(&:empty?)
      candidates.find { |path| File.directory?(path) } || '/Users/RPM'
    end

    def known_default_doorbell_reference_candidates
      [
        '/Users/Shared/Savant/Library/Application Support/RacePointMedia/systemConfig.rpmConfig/sounds/doorbell.wav',
        '/Users/Shared/Savant/Library/ApplicationSupport/RacePointMedia/systemConfig.rpmConfig/sounds/doorbell.wav',
        '/Users/RPM/Library/Application Support/RacePointMedia/systemConfig.rpmConfig/sounds/doorbell.wav',
        '/Users/RPM/Library/ApplicationSupport/RacePointMedia/systemConfig.rpmConfig/sounds/doorbell.wav',
        '/home/RPM/GNUstep/Library/ApplicationSupport/RacePointMedia/systemConfig.rpmConfig/sounds/doorbell.wav'
      ]
    end

    def reference_doorbell_audio_spec(discovery)
      candidates = []
      current = discovery[:current_reference]
      candidates << current[:resolved_path].to_s if current
      candidates.concat(known_default_doorbell_reference_candidates)
      candidates = candidates.map(&:to_s).map(&:strip).reject(&:empty?).uniq
      candidates.each do |path|
        next unless File.file?(path)
        metadata = wav_metadata_from_file(path)
        next unless metadata
        metadata[:source_path] = path
        return metadata
      end
      default_doorbell_reference_spec
    end

    def default_doorbell_reference_spec
      {
        codec: 'PCM (Int16)',
        audio_format: 1,
        channels: 2,
        sample_rate: 44_100,
        bits_per_sample: 16,
        block_align: 4,
        byte_rate: 176_400,
        frame_count: 111_708,
        data_size_bytes: 446_832,
        duration_seconds: 2.533061,
        source_path: 'canonical_default_savant_doorbell'
      }
    end

    def doorbell_assets_root
      File.join(File.dirname(@users_file), 'doorbell_audio')
    end

    def doorbell_custom_directory
      File.join(doorbell_assets_root, 'custom')
    end

    def doorbell_builtin_directory
      File.join(doorbell_assets_root, 'builtin')
    end

    def sanitize_doorbell_file_name(file_name)
      base = File.basename(file_name.to_s.strip)
      base = 'custom_doorbell.wav' if base.empty?
      base = base.gsub(/[^A-Za-z0-9._\-]/, '_')
      base = "#{base}.wav" unless base.downcase.end_with?('.wav')
      base
    end

    def afplay_path_token(path)
      path.to_s.gsub(' ', '\\ ')
    end

    def replace_doorbell_reference_tokens(content:, tokens:, replacement_token:)
      updated = content.to_s.dup
      needles = tokens.flat_map do |token|
        raw = token.to_s.strip
        next [] if raw.empty?
        unescaped = raw.gsub('\\ ', ' ')
        escaped = unescaped.gsub(' ', '\\ ')
        [raw, unescaped, escaped]
      end.flatten.uniq

      needles.each do |needle|
        next if needle.to_s.empty?
        updated = updated.gsub(needle, replacement_token)
      end

      default_patterns = [
        %r{~/Library/Application\\ Support/RacePointMedia/systemConfig\.rpmConfig/sounds/doorbell\.wav}i,
        %r{/Users/Shared/Savant/Library/Application(?:\\ | )Support/RacePointMedia/systemConfig\.rpmConfig/sounds/doorbell\.wav}i,
        %r{/Users/RPM/Library/Application(?:\\ | )Support/RacePointMedia/systemConfig\.rpmConfig/sounds/doorbell\.wav}i,
        %r{/home/RPM/GNUstep/Library/ApplicationSupport/RacePointMedia/systemConfig\.rpmConfig/sounds/doorbell\.wav}i
      ]
      default_patterns.each do |pattern|
        updated = updated.gsub(pattern, replacement_token)
      end
      updated
    end

    def write_content_with_optional_sudo(path:, content:, sudo_password:)
      if File.writable?(path)
        File.binwrite(path, content)
        return true
      end
      return false if sudo_password.to_s.strip.empty?

      tmp_dir = File.join(doorbell_assets_root, 'tmp')
      FileUtils.mkdir_p(tmp_dir)
      tmp_file = File.join(tmp_dir, "doorbell_patch_#{SecureRandom.hex(8)}.tmp")
      File.binwrite(tmp_file, content)
      cmd = "cp -p #{Shellwords.escape(tmp_file)} #{Shellwords.escape(path)}"
      sudo = run_with_sudo(cmd, sudo_password)
      sudo[:ok]
    ensure
      File.delete(tmp_file) if defined?(tmp_file) && tmp_file && File.exist?(tmp_file)
    end

    def run_with_sudo(command, sudo_password)
      payload = "printf '%s\\n' \"$SENTINEL_SUDO_PASSWORD\" | sudo -S -p '' sh -lc #{Shellwords.escape(command.to_s)}"
      stdout, status = Open3.capture2e({ 'SENTINEL_SUDO_PASSWORD' => sudo_password.to_s }, 'sh', '-lc', payload)
      {
        ok: status.success?,
        output: stdout.to_s.strip
      }
    rescue => e
      {
        ok: false,
        output: "#{e.class}:#{e.message}"
      }
    end

    def attempt_doorbell_service_reload
      return { attempted: false, ok: false, command: nil, output: 'sclibridge_not_found' } unless @sclibridge_path

      commands = [
        ['writestate', 'global.DoorbellReload', '1'],
        ['writestate', 'global.DoorEntryAudioInterruptReload', '1'],
        ['writestate', 'global.ReloadDoorbellService', '1']
      ]
      commands.each do |args|
        stdout, status = Open3.capture2e(@sclibridge_path, *args)
        output = stdout.to_s.strip
        next unless status.success?
        next if output.match?(/error|invalid|unknown|not found/i)
        return { attempted: true, ok: true, command: args.join(' '), output: output }
      end
      { attempted: true, ok: false, command: commands.first.join(' '), output: 'reload_state_not_confirmed' }
    rescue => e
      { attempted: true, ok: false, command: nil, output: "#{e.class}:#{e.message}" }
    end

    def ensure_builtin_doorbell_samples(reference_audio)
      FileUtils.mkdir_p(doorbell_builtin_directory)
      supported_format = reference_audio[:audio_format].to_i == 1 && reference_audio[:bits_per_sample].to_i == 16

      builtin_doorbell_sample_definitions.map do |sample|
        file_path = File.join(doorbell_builtin_directory, "#{sample[:id]}.wav")
        available = false
        reason = nil
        metadata = wav_metadata_from_file(file_path)

        if supported_format
          if metadata.nil? || !doorbell_audio_compatibility_errors(expected: reference_audio, actual: metadata).empty?
            bytes = build_sample_wav_bytes(sample: sample, reference_audio: reference_audio)
            if bytes
              File.binwrite(file_path, bytes)
              File.chmod(0o644, file_path) rescue nil
              metadata = wav_metadata_from_file(file_path)
            end
          end
          available = File.file?(file_path)
        else
          reason = 'reference_format_not_supported_for_builtin_generation'
        end

        {
          id: sample[:id],
          name: sample[:name],
          category: sample[:category],
          available: available ? true : false,
          reason: reason,
          file: file_path,
          metadata: metadata
        }
      end
    rescue => e
      @logger.warn("ensure_builtin_doorbell_samples failed #{e.class}: #{e.message}")
      []
    end

    def builtin_doorbell_sample_definitions
      [
        { id: 'classic_ding_dong', name: 'Classic Ding Dong', category: 'popular', score: [[784, 320, 80], [587, 520, 240], [523, 260, 60]] },
        { id: 'westminster_chime', name: 'Westminster Chime', category: 'popular', score: [[659, 250, 40], [784, 250, 40], [523, 250, 40], [587, 420, 180], [659, 260, 40], [523, 260, 40]] },
        { id: 'digital_two_tone', name: 'Digital Two Tone', category: 'popular', score: [[988, 150, 70], [740, 150, 70], [988, 150, 70], [740, 260, 160]] },
        { id: 'soft_home_chime', name: 'Soft Home Chime', category: 'popular', score: [[523, 220, 60], [659, 220, 60], [784, 340, 150], [659, 180, 60]] },
        { id: 'crystal_bells', name: 'Crystal Bells', category: 'popular', score: [[1046, 190, 40], [1318, 190, 40], [1568, 240, 140], [1318, 180, 40], [1046, 300, 180]] },
        { id: 'southpark_style', name: 'South Park Style (inspired)', category: 'themed', score: [[392, 180, 50], [523, 180, 50], [659, 220, 80], [523, 220, 70], [392, 340, 140]] },
        { id: 'super_mario_style', name: 'Super Mario Style (inspired)', category: 'themed', score: [[1318, 120, 50], [1568, 120, 50], [1046, 120, 50], [1318, 120, 50], [1760, 260, 140], [880, 260, 120]] },
        { id: 'starwars_style', name: 'Star Wars Style (inspired)', category: 'themed', score: [[440, 280, 40], [440, 280, 40], [440, 280, 40], [349, 220, 40], [523, 220, 70], [440, 300, 130]] },
        { id: 'simpsons_style', name: 'Simpsons Style (inspired)', category: 'themed', score: [[659, 140, 40], [880, 140, 40], [1046, 220, 80], [988, 140, 50], [784, 260, 120], [659, 280, 120]] },
        { id: 'wonderboy_style', name: 'Wonder Boy Style (inspired)', category: 'themed', score: [[784, 150, 35], [988, 150, 35], [1174, 170, 40], [1318, 190, 70], [988, 180, 50], [784, 240, 120]] }
      ]
    end

    def build_sample_wav_bytes(sample:, reference_audio:)
      sample_rate = reference_audio[:sample_rate].to_i
      channels = [reference_audio[:channels].to_i, 1].max
      bits = reference_audio[:bits_per_sample].to_i
      frames = reference_audio[:frame_count].to_i
      return nil if sample_rate <= 0 || bits != 16 || frames <= 100

      signal = Array.new(frames, 0.0)
      cursor = 0
      Array(sample[:score]).each do |segment|
        freq = segment[0].to_f
        duration_ms = segment[1].to_f
        pause_ms = segment[2].to_f
        tone_frames = (sample_rate * (duration_ms / 1000.0)).to_i
        pause_frames = (sample_rate * (pause_ms / 1000.0)).to_i
        break if cursor >= frames

        (0...tone_frames).each do |index|
          sample_index = cursor + index
          break if sample_index >= frames
          phase = (2.0 * Math::PI * freq * index) / sample_rate.to_f
          attack = [index.to_f / (sample_rate * 0.01), 1.0].min
          release = [((tone_frames - index).to_f / (sample_rate * 0.03)), 1.0].min
          envelope = [attack * release, 0.05].max
          signal[sample_index] += (Math.sin(phase) * 0.34 * envelope)
        end
        cursor += tone_frames + pause_frames
      end

      pcm = String.new.b
      signal.each do |sample_value|
        value = (sample_value * 32_767).round
        value = -32_768 if value < -32_768
        value = 32_767 if value > 32_767
        channels.times { pcm << [value].pack('s<') }
      end

      block_align = channels * (bits / 8)
      byte_rate = sample_rate * block_align
      data_size = pcm.bytesize
      riff_size = 36 + data_size
      header = +"RIFF"
      header << [riff_size].pack('V')
      header << 'WAVE'
      header << 'fmt '
      header << [16, 1, channels, sample_rate, byte_rate, block_align, bits].pack('VvvVVvv')
      header << 'data'
      header << [data_size].pack('V')
      header + pcm
    rescue => e
      @logger.warn("build_sample_wav_bytes failed #{e.class}: #{e.message}")
      nil
    end

    def wav_metadata_from_file(path)
      return nil unless File.file?(path)
      data = File.binread(path)
      wav_metadata_from_data(data)
    rescue
      nil
    end

    def wav_metadata_from_data(data)
      return nil unless data.is_a?(String) && data.bytesize >= 44
      return nil unless data.byteslice(0, 4) == 'RIFF' && data.byteslice(8, 4) == 'WAVE'

      offset = 12
      fmt = nil
      data_chunk_size = nil
      while (offset + 8) <= data.bytesize
        chunk_id = data.byteslice(offset, 4)
        chunk_size = data.byteslice(offset + 4, 4).unpack1('V')
        offset += 8
        break if chunk_size.nil? || chunk_size.negative?
        chunk_data = data.byteslice(offset, chunk_size) || ''.b

        if chunk_id == 'fmt ' && chunk_data.bytesize >= 16
          audio_format, channels, sample_rate, byte_rate, block_align, bits_per_sample = chunk_data.unpack('v v V V v v')
          fmt = {
            audio_format: audio_format.to_i,
            channels: channels.to_i,
            sample_rate: sample_rate.to_i,
            byte_rate: byte_rate.to_i,
            block_align: block_align.to_i,
            bits_per_sample: bits_per_sample.to_i
          }
        elsif chunk_id == 'data'
          data_chunk_size = chunk_size.to_i
        end

        offset += chunk_size
        offset += 1 if chunk_size.odd?
      end
      return nil unless fmt && data_chunk_size

      frame_count = fmt[:block_align].positive? ? (data_chunk_size / fmt[:block_align]) : 0
      duration_seconds = fmt[:byte_rate].positive? ? (data_chunk_size.to_f / fmt[:byte_rate].to_f) : 0.0
      {
        codec: wav_codec_label(fmt[:audio_format], fmt[:bits_per_sample]),
        audio_format: fmt[:audio_format],
        channels: fmt[:channels],
        sample_rate: fmt[:sample_rate],
        bits_per_sample: fmt[:bits_per_sample],
        block_align: fmt[:block_align],
        byte_rate: fmt[:byte_rate],
        frame_count: frame_count,
        data_size_bytes: data_chunk_size,
        duration_seconds: duration_seconds.round(6)
      }
    rescue => e
      @logger.debug("wav_metadata_from_data failed #{e.class}: #{e.message}")
      nil
    end

    def wav_codec_label(audio_format, bits_per_sample)
      case audio_format.to_i
      when 1
        "PCM (Int#{bits_per_sample.to_i})"
      when 3
        "IEEE Float (#{bits_per_sample.to_i}-bit)"
      when 6
        'A-Law'
      when 7
        'Mu-Law'
      else
        "WAV format #{audio_format}"
      end
    end

    def doorbell_audio_compatibility_errors(expected:, actual:)
      mismatches = []
      {
        audio_format: 'codec',
        channels: 'channel count',
        sample_rate: 'sample rate',
        bits_per_sample: 'bit depth',
        frame_count: 'duration frames'
      }.each do |key, label|
        next if expected[key].to_i == actual[key].to_i
        mismatches << "#{label} differs (expected #{expected[key]}, received #{actual[key]})"
      end
      mismatches
    end

    def can_manage_role?(session, role)
      case session['role'].to_s
      when 'integrator'
        %w[integrator home_admin home_user].include?(normalize_role(role))
      when 'home_admin'
        normalize_role(role) == 'home_user'
      else
        false
      end
    end

    def can_manage_user?(session, user)
      return false unless user
      return false if user['username'].to_s == @bootstrap_username && session['username'].to_s != @bootstrap_username
      can_manage_role?(session, user['role'])
    end

    def visible_users_for(session)
      case session['role'].to_s
      when 'integrator'
        @users.values.sort_by { |user| user['username'] }
      when 'home_admin'
        @users.values.select { |user| %w[integrator home_admin home_user].include?(user['role'].to_s) }.sort_by { |user| user['username'] }
      else
        [@users[session['username']]].compact
      end
    end

    def revoke_integrator_access(actor:)
      @policy['integrator_access_revoked'] = true
      @policy['integrator_access_revoked_at'] = Time.now.utc.iso8601
      @policy['integrator_access_revoked_by'] = actor.to_s
      @mutex.synchronize do
        @sessions.delete_if { |_token, value| value['role'].to_s == 'integrator' }
      end
      persist_store
    end

    def set_integrator_temporary_access(actor:, enabled:)
      if enabled
        @policy['integrator_access_temporarily_disabled'] = false
        @policy['integrator_access_temporarily_disabled_at'] = nil
        @policy['integrator_access_temporarily_disabled_by'] = nil
      else
        @policy['integrator_access_temporarily_disabled'] = true
        @policy['integrator_access_temporarily_disabled_at'] = Time.now.utc.iso8601
        @policy['integrator_access_temporarily_disabled_by'] = actor.to_s
        @mutex.synchronize do
          @sessions.delete_if { |_token, value| value['role'].to_s == 'integrator' }
        end
      end
      persist_store
    end

    def integrator_login_block_reason(username)
      user = @users[username.to_s]
      return nil unless user && user['enabled'] && user['role'].to_s == 'integrator'
      return 'integrator_access_revoked' if @policy['integrator_access_revoked']
      return 'integrator_access_temporarily_disabled' if @policy['integrator_access_temporarily_disabled']
      nil
    end

    def filtered_audit_events_for(session, limit:)
      events = read_audit_events(limit: limit)
      case session['role'].to_s
      when 'integrator'
        events
      when 'home_admin'
        events.select do |event|
          actor_name = event['actor'].to_s
          actor = @users[actor_name]
          role = actor ? actor['role'].to_s : ''
          role == 'integrator' || role == 'home_admin' || event['type'].to_s.start_with?('admin.user', 'integrator.access', 'monitoring.', 'auth.login')
        end
      else
        events.select { |event| event['actor'].to_s == session['username'].to_s }
      end
    end

    def normalize_harvest_mode(raw)
      mode = raw.to_s.strip.downcase
      return 'list_only' if mode == 'list_only'
      return 'live_only' if mode == 'live_only'
      return 'manifest_only' if mode == 'manifest_only'
      'hybrid'
    end

    def parse_state_list(raw)
      raw.to_s.split(/[;\n]/).map { |item| item.to_s.strip }.reject(&:empty?)
    end

    def resolve_harvest_state_list
      signature = [
        @harvest_mode,
        @harvest_state_list_raw,
        @harvest_manifest_file,
        @harvest_max_states,
        manifest_cache_key,
        live_discovery_cache_key
      ].join("\u0000")

      @mutex.synchronize do
        if @resolved_harvest_signature == signature && @resolved_harvest_state_list.any?
          return @resolved_harvest_state_list.dup
        end
      end

      explicit = parse_state_list(@harvest_state_list_raw)
      live = live_discovery_state_paths
      manifest = manifest_state_paths
      combined = case @harvest_mode
                 when 'list_only'
                   explicit
                 when 'live_only'
                   live
                 when 'manifest_only'
                   manifest
                 else
                   explicit + live + manifest + DEFAULT_DISCOVERY_SEEDS
                 end

      combined = combined.map(&:to_s).map(&:strip).reject(&:empty?).uniq
      combined = prioritize_harvest_paths(combined).first(@harvest_max_states)
      @mutex.synchronize do
        @resolved_harvest_state_list = combined
        @resolved_harvest_signature = signature
      end
      combined
    end

    def manifest_state_paths
      now = Time.now
      @mutex.synchronize do
        if (now - @last_manifest_refresh_at) < @manifest_refresh_interval
          return @manifest_cache[:paths].dup
        end
      end

      file = resolved_manifest_source
      if file.to_s.empty?
        @mutex.synchronize do
          @manifest_cache = { key: 'empty', paths: [] }
          @last_manifest_refresh_at = now
        end
        return []
      end

      paths = if File.directory?(file)
        Dir.glob(File.join(file, '*')).sort.flat_map { |path| load_manifest_paths(path) }
      elsif File.exist?(file)
        load_manifest_paths(file)
      else
        []
      end

      paths = paths.map(&:to_s).map(&:strip).reject(&:empty?).uniq
      @mutex.synchronize do
        @manifest_cache = { key: manifest_cache_key, paths: paths }
        @last_manifest_refresh_at = now
      end
      paths
    rescue => e
      @logger.error("manifest_state_paths failed #{e.class}: #{e.message}")
      []
    end

    def manifest_cache_key
      file = resolved_manifest_source
      return 'empty' if file.empty?
      return "missing:#{file}" unless File.exist?(file)

      if File.directory?(file)
        entries = Dir.glob(File.join(file, '*')).sort.map do |path|
          stat = File.stat(path)
          "#{path}:#{stat.size}:#{stat.mtime.to_i}"
        end
        "dir:#{entries.join('|')}"
      else
        stat = File.stat(file)
        "file:#{file}:#{stat.size}:#{stat.mtime.to_i}"
      end
    rescue
      "unknown:#{file}"
    end

    def resolved_manifest_source
      requested = @harvest_manifest_file.to_s.strip
      if auto_manifest_mode?(requested)
        generated = ensure_generated_manifest_from_live_statecenter
        return generated.to_s unless generated.to_s.empty?
        generated = ensure_generated_manifest_from_running_config
        return generated.to_s unless generated.to_s.empty?
      end
      requested
    end

    def auto_manifest_mode?(value)
      normalized = value.to_s.strip.downcase
      normalized.empty? || AUTO_MANIFEST_MODES.include?(normalized)
    end

    def live_discovery_state_paths
      return [] unless auto_manifest_mode?(@harvest_manifest_file)
      return [] unless @sclibridge_path

      file = ensure_generated_manifest_from_live_statecenter
      return [] if file.to_s.empty? || !File.exist?(file)

      load_manifest_paths(file)
    rescue => e
      @logger.error("live_discovery_state_paths failed #{e.class}: #{e.message}")
      []
    end

    def live_discovery_cache_key
      bucket = (@last_live_discovery_at.to_i / LIVE_DISCOVERY_REFRESH_SECONDS)
      "live:#{bucket}"
    rescue
      'live:0'
    end

    def ensure_generated_manifest_from_live_statecenter
      return '' unless @sclibridge_path

      now = Time.now
      @mutex.synchronize do
        if File.exist?(@generated_manifest_file) &&
           @manifest_cache[:generated_source] == 'statecenter' &&
           (now - @last_live_discovery_at) < LIVE_DISCOVERY_REFRESH_SECONDS
          return @generated_manifest_file
        end
      end

      discovered = discover_live_state_names
      return '' if discovered.empty?

      zones = discover_user_zones
      services = discover_services_for_zones(zones)
      candidates = discovered.select { |path| keep_live_discovered_manifest_state?(path) }
      candidates = prioritize_harvest_paths((candidates + DEFAULT_DISCOVERY_SEEDS).uniq).first(@harvest_max_states)

      FileUtils.mkdir_p(File.dirname(@generated_manifest_file))
      File.write(@generated_manifest_file, candidates.join("\n") + "\n")

      @mutex.synchronize do
        @last_live_discovery_at = now
        @manifest_cache[:generated_source] = 'statecenter'
        @manifest_cache[:generated_signature] = "statecenter:#{now.to_i}:#{candidates.length}"
        @manifest_cache[:generator_debug] = {
          discovery_source: 'sclibridge_statenames',
          running_rpm_config_directory: running_rpm_config_directory,
          discovered_state_count: discovered.length,
          selected_state_count: candidates.length,
          user_zone_count: zones.length,
          user_zone_samples: zones.first(12),
          zone_service_counts: services.transform_values(&:length),
          discovered_state_samples: discovered.first(20),
          selected_state_samples: candidates.first(20)
        }
      end
      @logger.info("generated live statecenter manifest with #{candidates.length} paths")
      @generated_manifest_file
    rescue => e
      @logger.error("ensure_generated_manifest_from_live_statecenter failed #{e.class}: #{e.message}")
      @mutex.synchronize do
        @manifest_cache[:generator_debug] = { generator_error: "#{e.class}: #{e.message}", discovery_source: 'sclibridge_statenames' }
      end
      ''
    end

    def ensure_generated_manifest_from_running_config
      rpm_dir = running_rpm_config_directory
      return '' if rpm_dir.to_s.empty?

      service_file = File.join(rpm_dir, 'serviceImplementation.xml')
      profiles_dir = File.join(rpm_dir, 'componentProfiles')
      return '' unless File.exist?(service_file) && File.directory?(profiles_dir)

      cache_signature = [
        rpm_dir,
        file_signature(service_file),
        directory_signature(profiles_dir),
        file_signature(File.join(rpm_dir, 'dataTableInfo.plist')),
        file_signature(File.join(rpm_dir, 'ldt.plist'))
      ].join('|')

      if File.exist?(@generated_manifest_file) && @manifest_cache[:generated_signature] == cache_signature
        return @generated_manifest_file
      end

      service_map = parse_active_services(service_file)
      plist_debug = plist_debug_payload(rpm_dir)
      zone_paths = zone_summary_state_paths(rpm_dir)
      exact_paths = exact_runtime_state_paths_from_data_tables(rpm_dir)
      candidates = generate_manifest_candidates_from_running_config(rpm_dir)
      FileUtils.mkdir_p(File.dirname(@generated_manifest_file))
      File.write(@generated_manifest_file, candidates.join("\n") + "\n")
      @manifest_cache[:generated_signature] = cache_signature
      @manifest_cache[:generator_debug] = {
        running_rpm_config_directory: rpm_dir,
        rpm_config_found: true,
        service_file_exists: File.exist?(service_file),
        profiles_dir_exists: File.directory?(profiles_dir),
        active_service_count: service_map.length,
        profile_count: Dir.glob(File.join(profiles_dir, '*.xml')).length,
        plist_debug: plist_debug,
        zone_summary_state_count: zone_paths.length,
        exact_runtime_state_count: exact_paths.length,
        generated_manifest_state_count: candidates.length,
        zone_summary_samples: zone_paths.first(12),
        exact_runtime_samples: exact_paths.first(12),
        generated_manifest_samples: candidates.first(20)
      }
      @manifest_cache[:generated_source] = 'running_config'
      @logger.info("generated host manifest with #{candidates.length} paths from #{rpm_dir}")
      @generated_manifest_file
    rescue => e
      @logger.error("ensure_generated_manifest_from_running_config failed #{e.class}: #{e.message}")
      @manifest_cache[:generator_debug] = { generator_error: "#{e.class}: #{e.message}" }
      ''
    end

    def running_rpm_config_directory
      candidates = []

      script_dir = File.expand_path(File.dirname(__FILE__))
      candidates << File.expand_path('..', script_dir) if File.basename(script_dir) == 'CustomerFiles'

      rpm_config_path_candidates.each { |path| candidates << path }

      candidates.find do |path|
        File.exist?(File.join(path, 'serviceImplementation.xml')) &&
          File.directory?(File.join(path, 'componentProfiles'))
      end.to_s
    end

    def active_config_filename
      rpm_dir = running_rpm_config_directory
      unless rpm_dir.to_s.empty?
        resolved = File.realpath(rpm_dir) rescue rpm_dir
        base = File.basename(resolved.to_s)
        return base unless base == 'userConfig.rpmConfig'
      end

      detect_active_config_from_states
    rescue
      ''
    end

    def file_signature(path)
      stat = File.stat(path)
      "#{path}:#{stat.size}:#{stat.mtime.to_i}"
    rescue
      "#{path}:missing"
    end

    def directory_signature(path)
      Dir.glob(File.join(path, '*.xml')).sort.map { |item| file_signature(item) }.join('|')
    rescue
      "#{path}:missing"
    end

    Candidate = Struct.new(:path, :source_component, :logical_component, keyword_init: true)

    def generate_manifest_candidates_from_running_config(rpm_dir)
      exact_paths = exact_runtime_state_paths_from_data_tables(rpm_dir)
      exact_paths.concat(zone_summary_state_paths(rpm_dir))
      exact_paths.concat(global_summary_state_paths)
      service_map = parse_active_services(File.join(rpm_dir, 'serviceImplementation.xml'))
      profile_paths = Dir.glob(File.join(rpm_dir, 'componentProfiles', '*.xml')).sort

      candidates = []
      profile_paths.each do |profile_path|
        xml = REXML::Document.new(File.read(profile_path))
        candidates.concat(profile_candidates(xml, service_map))
      rescue => e
        @logger.warn("profile parse failed #{profile_path} #{e.class}: #{e.message}")
      end

      deduped = {}
      candidates.each do |candidate|
        next unless keep_generated_manifest_state?(candidate.path, exact_paths)
        deduped[candidate.path] ||= candidate
      end
      exact_paths.each do |path|
        deduped[path] ||= Candidate.new(path: path, source_component: 'runtime_data_table', logical_component: 'exact_runtime')
      end
      deduped.keys.sort
    end

    def cached_generator_debug_payload
      debug = @manifest_cache[:generator_debug]
      return debug if debug.is_a?(Hash) && !debug.empty?

      rpm_dir = running_rpm_config_directory
      return {
        running_rpm_config_directory: rpm_dir,
        rpm_config_found: !rpm_dir.to_s.empty?
      }
    end

    def discover_live_state_names
      full = run_sclibridge_lines('statenames')
      names = full[:status].success? ? full[:lines] : []

      if names.empty?
        fallback_filters = [
          'global',
          'Generic_component',
          'Room',
          'Status',
          'SVC_',
          'Hue',
          'Garage',
          'Door',
          'Lock',
          'Security',
          'Temperature',
          'Thermostat',
          'Config',
          'IPAddress',
          'SystemRole',
          'CPU',
          'Uptime'
        ]

        names = fallback_filters.flat_map do |filter|
          result = run_sclibridge_lines('statenames', filter)
          result[:status].success? ? result[:lines] : []
        end
      end

      names.map(&:to_s).map(&:strip).reject(&:empty?).uniq
    rescue => e
      @logger.warn("discover_live_state_names failed #{e.class}: #{e.message}")
      []
    end

    def discover_user_zones
      result = run_sclibridge_lines('userzones')
      return [] unless result[:status].success?

      result[:lines].map(&:to_s).map(&:strip).reject(&:empty?).uniq
    rescue => e
      @logger.warn("discover_user_zones failed #{e.class}: #{e.message}")
      []
    end

    def discover_services_for_zones(zones)
      zones.each_with_object({}) do |zone, memo|
        result = run_sclibridge_lines('servicesforzone', zone)
        memo[zone] = result[:status].success? ? result[:lines].map(&:to_s).map(&:strip).reject(&:empty?).uniq : []
      end
    rescue => e
      @logger.warn("discover_services_for_zones failed #{e.class}: #{e.message}")
      {}
    end

    def plist_debug_payload(rpm_dir)
      global_zone = plist_json(File.join(rpm_dir, 'globalZoneOrganization.plist'))
      zone_info = plist_json(File.join(rpm_dir, 'zoneInfo.plist'))
      data_table = plist_json(File.join(rpm_dir, 'dataTableInfo.plist'))
      global_zone_text = zone_names_from_global_zone_text(File.join(rpm_dir, 'globalZoneOrganization.plist'))
      zone_info_text = zone_names_from_zone_info_text(File.join(rpm_dir, 'zoneInfo.plist'))
      lighting_rows_text = lighting_rows_from_data_table_xml(File.join(rpm_dir, 'dataTableInfo.plist'))

      {
        global_zone_organization_exists: File.exist?(File.join(rpm_dir, 'globalZoneOrganization.plist')),
        zone_info_exists: File.exist?(File.join(rpm_dir, 'zoneInfo.plist')),
        data_table_info_exists: File.exist?(File.join(rpm_dir, 'dataTableInfo.plist')),
        global_zone_organization_class: global_zone.class.to_s,
        zone_info_class: zone_info.class.to_s,
        data_table_info_class: data_table.class.to_s,
        global_zone_order_count: Array(global_zone.is_a?(Hash) ? global_zone['RPMZoneOrderList'] : []).length,
        zone_info_zone_count: zone_info_zone_count(zone_info),
        lighting_row_count: Array(data_table.is_a?(Hash) ? data_table.dig('Lighting', 'Lighting') : []).length,
        global_zone_text_count: global_zone_text.length,
        zone_info_text_count: zone_info_text.length,
        lighting_row_text_count: lighting_rows_text.length,
        global_zone_identifiers_sample: Array(global_zone.is_a?(Hash) ? global_zone['RPMZoneOrderList'] : []).map { |row| row['Identifier'].to_s }.reject(&:empty?).first(10),
        zone_info_identifiers_sample: zone_info_zone_names(zone_info).first(10),
        global_zone_text_sample: global_zone_text.first(10),
        zone_info_text_sample: zone_info_text.first(10),
        lighting_row_text_sample: lighting_rows_text.first(3)
      }
    rescue => e
      { plist_debug_error: "#{e.class}: #{e.message}" }
    end

    def zone_info_zone_count(zone_info)
      zone_info_zone_names(zone_info).length
    end

    def zone_info_zone_names(zone_info)
      return [] unless zone_info.is_a?(Hash)

      zone_info.each_with_object([]) do |(name, payload), zones|
        next unless payload.is_a?(Hash)
        next unless payload['RPMZoneItemClass'].to_s == 'RPMZoneItem'
        normalized = name.to_s.strip
        next if normalized.empty?
        zones << normalized
      end
    end

    def parse_active_services(path)
      return [] unless File.exist?(path)

      services = []
      File.foreach(path) do |line|
        next unless line.include?('<service ')
        next unless line.include?(' enabled="true"')

        component = line[/source_component_name="([^"]+)"/, 1].to_s.strip
        logical = line[/source_logical_component="([^"]+)"/, 1].to_s.strip
        next if component.empty?

        services << {
          source_component_name: component,
          source_logical_component: logical
        }
      end
      services
    end

    def profile_candidates(xml, service_map)
      logical_metadata = extract_logical_metadata(xml)
      logicals = logical_metadata.keys
      matched_services = service_map.select do |service|
        logical = service[:source_logical_component].to_s
        logical.empty? ? logicals.include?('') : logicals.include?(logical)
      end

      candidates = []
      matched_services.each do |service|
        logical = service[:source_logical_component].to_s
        metadata = logical_metadata[logical]
        next unless metadata

        metadata[:bindings].each do |binding|
          candidates << Candidate.new(
            path: "#{service[:source_component_name]}.#{binding}",
            source_component: service[:source_component_name],
            logical_component: logical
          )
        end

        metadata[:status_states].each do |state_name|
          candidates << Candidate.new(
            path: "#{service[:source_component_name]}.#{state_name}",
            source_component: service[:source_component_name],
            logical_component: logical
          )
        end
      end
      candidates
    end

    def extract_logical_metadata(xml)
      metadata = {}
      xml.elements.each('//logical_component') do |node|
        logical = node.attributes['logical_component_name'].to_s.strip
        metadata[logical] = {
          bindings: binding_names(xml, logical),
          status_states: status_state_names(node)
        }
      end
      metadata
    end

    def binding_names(xml, logical)
      names = []
      xml.elements.each("//dynamic_state_variable[@owning_logical_component='#{logical}']") do |node|
        binding = node.attributes['state_center_binding'].to_s.strip
        names << binding unless binding.empty?
      end
      xml.elements.each("//state_variable[@owning_logical_component='#{logical}'][@state_center_binding]") do |node|
        binding = node.attributes['state_center_binding'].to_s.strip
        names << binding unless binding.empty?
      end
      names.uniq
    end

    def status_state_names(logical_node)
      names = []
      logical_node.get_elements('./status_messages/status_message').each do |status_message|
        status_message.elements.each('.//update') do |update|
          state = update.attributes['state'].to_s.strip
          names << state unless state.empty?
        end
        status_message.elements.each('.//update_state_variable') do |update|
          state = update.attributes['name'].to_s.strip
          names << state unless state.empty?
        end
      end
      names.uniq
    end

    def exact_runtime_state_paths_from_data_tables(rpm_dir)
      data = plist_json(File.join(rpm_dir, 'dataTableInfo.plist'))

      exact_paths = []

      lighting_rows = Array(data.is_a?(Hash) ? data.dig('Lighting', 'Lighting') : [])
      lighting_rows = lighting_rows_from_data_table_xml(File.join(rpm_dir, 'dataTableInfo.plist')) if lighting_rows.empty?
      return [] if lighting_rows.empty?
      hue_ids = lighting_rows.map do |row|
        next unless row.is_a?(Hash)
        next unless row['Controller'].to_s == 'Hue Lighting Controller'
        address = row['Address1'].to_s.strip
        next unless address.match?(/\A\d+\z/)
        id = address.to_i
        next if id <= 0
        id
      end.compact.uniq.sort

      hue_ids.each do |id|
        exact_paths << "Hue Lighting Controller.BulbName_#{id}"
        exact_paths << "Hue Lighting Controller.isLightOn_#{id}"
        exact_paths << "Hue Lighting Controller.LightPowerStatus_#{id}"
      end

      group_ids = lighting_rows.map do |row|
        next unless row.is_a?(Hash)
        next unless row['Controller'].to_s == 'Hue Lighting Controller'
        type = row['Type'].to_s.strip
        next unless type.casecmp('Scene').zero? || type.casecmp('Group').zero?
        address = row['Address1'].to_s.strip
        next unless address.match?(/\A\d+\z/)
        id = address.to_i
        next if id <= 0
        id
      end.compact.uniq.sort

      group_ids.each do |id|
        exact_paths << "Hue Lighting Controller.GroupName_#{id}"
        exact_paths << "Hue Lighting Controller.GroupisLightOn_#{id}"
      end

      exact_paths.uniq
    rescue => e
      @logger&.warn("exact_runtime_state_paths_from_data_tables failed #{e.class}: #{e.message}")
      []
    end

    def zone_summary_state_paths(rpm_dir)
      zones = zone_names_from_global_zone_organization(rpm_dir)
      zones = zone_names_from_zone_info(rpm_dir) if zones.empty?

      suffixes = %w[
        ActiveService
        ActiveAudioService
        ActiveVideoService
        ActiveServices
        BrightnessLevel
        ConfigurationStatus
        ConfigurationStatusIsGreen
        ConfigurationStatusIsYellow
        ConfigurationStatusIsRed
        ConfigurationStatusIsGrey
        ConfigurationStatusLight
        ControllerStatus
        ControllerStatusIsGreen
        ControllerStatusIsYellow
        ControllerStatusIsRed
        ControllerStatusIsGrey
        ControllerStatusLight
        ControlStatus
        ControlStatusIsGreen
        ControlStatusIsYellow
        ControlStatusIsRed
        ControlStatusIsGrey
        ControlStatusLight
        LightsAreOn
        NumberOfLightsOn
        RoomLightsAreOn
        RoomNumberOfLightsOn
        RoomNumberOfShadesOpen
        RoomCurrentTemperature
        CurrentTemperature
        ContentProtectionIssues
        RoomImageUID
        SecurityStatus
        NumberOfSecurityFaults
        SystemStatus
        SystemStatusIsGreen
        SystemStatusIsYellow
        SystemStatusIsRed
        SystemStatusIsGrey
        SystemStatusLight
      ]

      zones.flat_map do |zone|
        suffixes.map { |suffix| "#{zone}.#{suffix}" }
      end
    rescue => e
      @logger&.warn("zone_summary_state_paths failed #{e.class}: #{e.message}")
      []
    end

    def zone_names_from_global_zone_organization(rpm_dir)
      data = plist_json(File.join(rpm_dir, 'globalZoneOrganization.plist'))
      zones = Array(data.is_a?(Hash) ? data['RPMZoneOrderList'] : []).map { |row| row['Identifier'].to_s.strip }.reject(&:empty?)
      return zones unless zones.empty?
      zone_names_from_global_zone_text(File.join(rpm_dir, 'globalZoneOrganization.plist'))
    rescue => e
      @logger&.warn("zone_names_from_global_zone_organization failed #{e.class}: #{e.message}")
      []
    end

    def zone_names_from_zone_info(rpm_dir)
      data = plist_json(File.join(rpm_dir, 'zoneInfo.plist'))
      zones = zone_info_zone_names(data)
      return zones unless zones.empty?
      zone_names_from_zone_info_text(File.join(rpm_dir, 'zoneInfo.plist'))
    rescue => e
      @logger&.warn("zone_names_from_zone_info failed #{e.class}: #{e.message}")
      []
    end

    def zone_names_from_global_zone_text(path)
      return [] unless File.exist?(path)

      File.read(path)
        .scan(/<key>Identifier<\/key>\s*<string>([^<]+)<\/string>/m)
        .flatten
        .map(&:strip)
        .reject(&:empty?)
        .uniq
    rescue => e
      @logger&.warn("zone_names_from_global_zone_text failed #{e.class}: #{e.message}")
      []
    end

    def zone_names_from_zone_info_text(path)
      return [] unless File.exist?(path)

      zones = []
      File.read(path).scan(/<key>([^<]+)<\/key>\s*<dict>(.*?)<\/dict>/m).each do |name, body|
        next unless body.include?('<key>RPMZoneItemClass</key>') && body.include?('<string>RPMZoneItem</string>')
        normalized = name.to_s.strip
        next if normalized.empty?
        zones << normalized
      end
      zones.uniq
    rescue => e
      @logger&.warn("zone_names_from_zone_info_text failed #{e.class}: #{e.message}")
      []
    end

    def lighting_rows_from_data_table_xml(path)
      return [] unless File.exist?(path)

      rows = []
      File.read(path).scan(/<dict>(.*?)<\/dict>/m).each do |match|
        body = match.first
        next unless body.include?('<key>Controller</key>') && body.include?('Hue Lighting Controller')
        row = {}
        body.scan(/<key>([^<]+)<\/key>\s*(?:<string>(.*?)<\/string>|<integer>(.*?)<\/integer>|<real>(.*?)<\/real>|<(true|false)\/>)/m) do |key, string_value, integer_value, real_value, bool_value|
          row[key] = (string_value || integer_value || real_value || bool_value).to_s
        end
        rows << row unless row.empty?
      end
      rows
    rescue => e
      @logger&.warn("lighting_rows_from_data_table_xml failed #{e.class}: #{e.message}")
      []
    end

    def global_summary_state_paths
      [
        'global.AcceptingUIConnections',
        'global.ActiveZones',
        'global.AllChassisActive',
        'global.AllProcessesStarted',
        'global.CurrentMinute',
        'global.CurrentHour',
        'global.CurrentDate',
        'global.CurrentDay',
        'global.CurrentMonth',
        'global.CurrentSecond',
        'global.CurrentTime',
        'global.Dawn',
        'global.Dusk',
        'global.HostLighting',
        'global.LightsAreOn',
        'global.SystemHasStarted',
        'global.SystemIsReady',
        'global.SystemStatus',
        'global.SystemStatusIsGreen',
        'global.SystemStatusIsYellow',
        'global.SystemStatusIsRed',
        'global.SystemStatusIsGrey',
        'global.SystemStatusLight',
        'global.ControlStatus',
        'global.ControlStatusIsGreen',
        'global.ControlStatusIsYellow',
        'global.ControlStatusIsRed',
        'global.ControlStatusIsGrey',
        'global.ControlStatusLight',
        'global.ControllerStatus',
        'global.ControllerStatusIsGreen',
        'global.ControllerStatusIsYellow',
        'global.ControllerStatusIsRed',
        'global.ControllerStatusIsGrey',
        'global.ControllerStatusLight',
        'global.ConfigurationStatus',
        'global.ConfigurationStatusIsGreen',
        'global.ConfigurationStatusIsYellow',
        'global.ConfigurationStatusIsRed',
        'global.ConfigurationStatusIsGrey',
        'global.ConfigurationStatusLight',
        'global.DiagnosticReportStatus',
        'global.DiagnosticReportStatusIsGreen',
        'global.DiagnosticReportStatusIsYellow',
        'global.DiagnosticReportStatusIsRed',
        'global.DiagnosticReportStatusIsGrey',
        'global.DiagnosticReportStatusLight',
        'global.ContentProtectionIssues',
        'global.BrightnessLevel',
        'global.HostSoftwareInstallDate',
        'global.HostSoftwareVersion',
        'global.ExternalUpdateVersion',
        'global.ExternalUpdateServer',
        'global.ExternalUpdateOTAState',
        'global.Hue Lighting Controller.ControlIsConnected',
        'global.iOS Savant Sentinel.ControlIsConnected',
        'global.rubi',
        'global.rubierror'
      ]
    end

    def plist_json(path)
      return nil unless File.exist?(path)

      stdout, status = Open3.capture2e('plutil', '-convert', 'json', '-o', '-', path)
      return JSON.parse(stdout) if status.success?

      xml = REXML::Document.new(File.read(path))
      plist_root = xml.root
      return nil unless plist_root

      value_node = plist_root.elements.to_a.find { |node| %w[dict array string integer real true false].include?(node.name) }
      return nil unless value_node

      plist_value_to_ruby(value_node)
    rescue => e
      @logger&.warn("plist_json #{path} failed #{e.class}: #{e.message}")
      nil
    end

    def plist_value_to_ruby(node)
      case node.name
      when 'dict'
        children = node.elements.to_a
        result = {}
        index = 0
        while index < children.length
          key_node = children[index]
          value_node = children[index + 1]
          break unless key_node && value_node
          if key_node.name == 'key'
            result[key_node.text.to_s] = plist_value_to_ruby(value_node)
          end
          index += 2
        end
        result
      when 'array'
        node.elements.to_a.map { |child| plist_value_to_ruby(child) }
      when 'string'
        node.text.to_s
      when 'integer'
        node.text.to_i
      when 'real'
        node.text.to_f
      when 'true'
        true
      when 'false'
        false
      else
        node.text.to_s
      end
    end

    def keep_generated_manifest_state?(path, exact_paths = [])
      return true if %w[
        Generic_component.APIServerStatus
        Generic_component.APILastError
        Generic_component.HarvestLastError
        Generic_component.HarvestStateCount
        Generic_component.HarvestStatus
      ].include?(path)

      return true if path.match?(/\.(RoomNumberOfLightsOn|NumberOfLightsOn|RoomNumberOfShadesOpen|RoomCurrentTemperature|CurrentTemperature|ZoneIsActive|ActiveService|ActiveAudioService|ActiveVideoService|ActiveServices|SecurityStatus|NumberOfSecurityFaults|GarageDoorStatus|MagLockStatus\d*|DoorLockStatus_\d+|IsDoorLocked_\d+)\z/)
      return true if path.match?(/\.SVC_(AV|ENV_SECURITYCAMERA|ENV_SECURITYSYSTEM|ENV_DOORLOCK)\.Service(State|IsActive)\z/)
      return true if path.match?(/\.(SystemStatusIsGreen|SystemStatusIsYellow|SystemStatusIsRed|ControllerStatusIsGreen|ControllerStatusIsYellow|ControllerStatusIsRed|ControlStatusIsGreen|ControlStatusIsYellow|ControlStatusIsRed|ConfigurationStatusIsGreen|ConfigurationStatusIsYellow|ConfigurationStatusIsRed)\z/)
      return true if path.match?(/\.(SystemStatus|ControllerStatus|ControlStatus|ConfigurationStatus|DiagnosticReportStatus|ContentProtectionIssues|SystemRole|IPAddress|OSVersion|SoftwareVersion|CurrentConfigName|CurrentLoadedConfigName|LoadedConfigName|ConfigName|ConfigurationName|SysStatus\.CPUPercent|SysStatus\.CPULoad|SysStatus\.Uptime\.(Years|Months|Days|Hours|Minutes|Seconds))\z/)

      if path.start_with?('Hue Lighting Controller.')
        suffix = path.delete_prefix('Hue Lighting Controller.')
        return true if %w[CurrentLightNumber CurrentGroupNumber UserName DeviceType].include?(suffix)
        return true if exact_paths.include?(path)
        return false if suffix.match?(/\A(isLightOn|LightPowerStatus|BulbName|GroupisLightOn|GroupName)_\d+\z/)
      end

      false
    end

    def keep_live_discovered_manifest_state?(path)
      return true if keep_generated_manifest_state?(path)
      return true if path.start_with?('global.') && path.match?(/\.[A-F0-9]{8,}\./i)
      return true if path.match?(/\.(ActiveZone|ZoneIsActive|CurrentSource|SourceName|CurrentScene|SceneName|ServiceIsActive|ServiceState)\z/)
      return true if path.match?(/\A[^.]+\.(BulbName|isLightOn|LightPowerStatus|GroupisLightOn|GroupName)_\d+\z/)
      false
    end

    def prioritize_harvest_paths(paths)
      paths.sort_by do |path|
        [harvest_priority(path), path.length, path]
      end
    end

    def harvest_priority(path)
      return 0 if DEFAULT_DISCOVERY_SEEDS.include?(path)
      return 1 if path.start_with?('global.') && path.match?(/\.(SystemStatus|SystemStatusIsGreen|SystemStatusIsYellow|SystemStatusIsRed|SystemStatusIsGrey|SystemStatusLight|ControlStatus|ControlStatusIsGreen|ControlStatusIsYellow|ControlStatusIsRed|ControlStatusIsGrey|ControlStatusLight|ControllerStatus|ControllerStatusIsGreen|ControllerStatusIsYellow|ControllerStatusIsRed|ControllerStatusIsGrey|ControllerStatusLight|ConfigurationStatus|ConfigurationStatusIsGreen|ConfigurationStatusIsYellow|ConfigurationStatusIsRed|ConfigurationStatusIsGrey|ConfigurationStatusLight|DiagnosticReportStatus|DiagnosticReportStatusIsGreen|DiagnosticReportStatusIsYellow|DiagnosticReportStatusIsRed|DiagnosticReportStatusIsGrey|DiagnosticReportStatusLight)\z/)
      return 2 if path.start_with?('global.') && path.match?(/\.(CurrentTime|CurrentDate|CurrentDay|CurrentMonth|CurrentHour|CurrentMinute|CurrentSecond|AllChassisActive|AllProcessesStarted|AcceptingUIConnections|HostSoftwareInstallDate|HostSoftwareVersion|LightsAreOn|SystemIsReady|SystemHasStarted|ExternalUpdateVersion|ExternalUpdateServer|ExternalUpdateOTAState)\z/)
      return 3 if path.match?(/\.(SystemRole|IPAddress|OSVersion|SoftwareVersion|CurrentConfigName|CurrentLoadedConfigName|LoadedConfigName|ConfigName|ConfigurationName|SysStatus\.CPUPercent|SysStatus\.CPULoad|SysStatus\.Uptime\.(Years|Months|Days|Hours|Minutes|Seconds))\z/)
      return 4 if path.match?(/\.(ConfigurationStatus|ConfigurationStatusIsGreen|ConfigurationStatusIsYellow|ConfigurationStatusIsRed|ConfigurationStatusIsGrey|ControllerStatus|ControllerStatusIsGreen|ControllerStatusIsYellow|ControllerStatusIsRed|ControllerStatusIsGrey|ControlStatus|ControlStatusIsGreen|ControlStatusIsYellow|ControlStatusIsRed|ControlStatusIsGrey|SystemStatus|SystemStatusIsGreen|SystemStatusIsYellow|SystemStatusIsRed|SystemStatusIsGrey)\z/)
      return 5 if path.match?(/\.(RoomNumberOfLightsOn|NumberOfLightsOn|LightsAreOn|RoomNumberOfShadesOpen|RoomCurrentTemperature|CurrentTemperature|ActiveService|ActiveAudioService|ActiveVideoService|ActiveServices|SecurityStatus|NumberOfSecurityFaults)\z/)
      return 6 if path.match?(/\.SVC_(AV|ENV_SECURITYCAMERA|ENV_SECURITYSYSTEM|ENV_DOORLOCK)\.Service(State|IsActive)\z/)
      return 7 if path.match?(/\.(IsOutputRelayOn|IsShadeOpen|IsShadeClosed|Position|ThermostatCurrentTemperature|ThermostatCurrentSetPoint|GarageDoorStatus|MagLockStatus\d*|DoorLockStatus_\d+|IsDoorLocked_\d+)\z/)
      20
    end

    def load_manifest_paths(path)
      return [] unless File.file?(path)

      ext = File.extname(path).downcase
      case ext
      when '.json'
        parse_manifest_json(path)
      when '.csv'
        parse_manifest_csv(path)
      else
        parse_manifest_text(path)
      end
    rescue => e
      @logger.error("load_manifest_paths #{path} failed #{e.class}: #{e.message}")
      []
    end

    def parse_manifest_json(path)
      parsed = JSON.parse(File.read(path))
      if parsed.is_a?(Array)
        parsed.map(&:to_s)
      elsif parsed.is_a?(Hash)
        keys = %w[paths states state_paths harvest_state_list harvest_paths]
        key = keys.find { |item| parsed.key?(item) }
        Array(key ? parsed[key] : []).map(&:to_s)
      else
        []
      end
    end

    def parse_manifest_csv(path)
      rows = CSV.read(path, headers: true)
      return [] if rows.empty?

      headers = rows.headers.map { |item| item.to_s.strip.downcase }
      path_header = headers.find { |item| %w[path state_path state binding].include?(item) }
      return [] unless path_header

      rows.map { |row| row[path_header].to_s.strip }.reject(&:empty?)
    end

    def parse_manifest_text(path)
      File.read(path).split(/[;\n\r]/).map { |item| item.to_s.strip }.reject(&:empty?)
    end

    def detect_sclibridge_path
      candidates = [
        '/Users/Shared/Savant/Applications/RacePointMedia/sclibridge',
        '/Users/RPM/Applications/RacePointMedia/sclibridge',
        '/home/RPM/Applications/RacePointMedia/sclibridge',
        '/usr/local/bin/sclibridge'
      ]
      candidates.find { |path| File.exist?(path) }
    end

    def rpm_config_path_candidates
      [
        '/Users/Shared/Savant/Library/Application Support/RacePointMedia/userConfig.rpmConfig',
        '/Users/Shared/Savant/Library/ApplicationSupport/RacePointMedia/userConfig.rpmConfig',
        '/home/RPM/GNUstep/Library/ApplicationSupport/RacePointMedia/userConfig.rpmConfig',
        '/Users/RPM/GNUstep/Library/ApplicationSupport/RacePointMedia/userConfig.rpmConfig',
        '/Users/RPM/Library/Application Support/RacePointMedia/userConfig.rpmConfig',
        '/Users/RPM/Library/ApplicationSupport/RacePointMedia/userConfig.rpmConfig'
      ]
    end

    def run_sclibridge_lines(*args)
      return { lines: [], status: nil, output: 'sclibridge_not_found' } unless @sclibridge_path

      stdout, status = Open3.capture2e(@sclibridge_path, *args.map(&:to_s))
      {
        lines: stdout.to_s.split(/\r?\n/, -1).map(&:rstrip).reject { |line| line == '' },
        status: status,
        output: stdout.to_s
      }
    rescue => e
      {
        lines: [],
        status: nil,
        output: "#{e.class}:#{e.message}"
      }
    end

    def read_statecenter_value(state_path)
      return [nil, 'empty_state_path'] if state_path.to_s.strip.empty?
      return [nil, 'sclibridge_not_found'] unless @sclibridge_path

      stdout, status = Open3.capture2e(@sclibridge_path, 'readstate', state_path.to_s)
      if status.success?
        [stdout.to_s.strip, nil]
      else
        [nil, stdout.to_s.strip.empty? ? 'readstate_failed' : stdout.to_s.strip]
      end
    rescue => e
      [nil, "#{e.class}:#{e.message}"]
    end

    def read_statecenter_values(state_paths)
      now = Time.now.utc.iso8601
      return {} if state_paths.empty?
      return state_paths.each_with_object({}) { |path, memo| memo[path] = { 'value' => nil, 'error' => 'sclibridge_not_found', 'at' => now } } unless @sclibridge_path

      stdout, status = Open3.capture2e(@sclibridge_path, 'readstate', *state_paths.map(&:to_s))
      unless status.success?
        error = stdout.to_s.strip.empty? ? 'readstate_failed' : stdout.to_s.strip
        return state_paths.each_with_object({}) { |path, memo| memo[path] = { 'value' => nil, 'error' => error, 'at' => now } }
      end

      lines = stdout.to_s.split(/\r?\n/, -1).map(&:rstrip)
      lines.pop while lines.any? && lines.last == ''
      state_paths.each_with_index.each_with_object({}) do |(path, index), memo|
        memo[path] = {
          'value' => index < lines.length ? lines[index] : nil,
          'error' => '',
          'at' => now
        }
      end
    rescue => e
      state_paths.each_with_object({}) do |path, memo|
        memo[path] = { 'value' => nil, 'error' => "#{e.class}:#{e.message}", 'at' => now }
      end
    end

    def next_harvest_slice(resolved)
      return resolved if resolved.length <= 240

      @harvest_cycle_count += 1
      batch_size = effective_harvest_batch_size(resolved.length)
      start_index = @harvest_cursor % resolved.length
      slice = resolved.drop(start_index).first(batch_size)
      if slice.length < batch_size
        slice += resolved.first(batch_size - slice.length)
      end
      @harvest_cursor = (start_index + batch_size) % resolved.length
      slice
    end

    def effective_harvest_batch_size(total_states)
      return total_states if total_states <= 240
      return 300 if total_states <= 1_000
      return 450 if total_states <= 2_500
      return 650 if total_states <= 4_500
      return 900 if total_states <= 7_000
      1_000
    end
  end

  @bridge = nil

  class << self
    def dispatch(command_string)
      parts = command_string.to_s.split(',')
      cmd = parts.shift.to_s

      case cmd
      when 'bridge_start'
        bind_host, port, use_https, tls_cert_file, tls_key_file, log_directory, log_level, users_file, bootstrap_username, bootstrap_password, bootstrap_config_revision, integrator_reset_flag, harvest_state_list, harvest_poll_seconds, harvest_mode, harvest_manifest_file, harvest_max_states = parts
        @bridge&.stop
        @bridge = Bridge.new(
          bind_host: bind_host,
          port: port,
          log_directory: log_directory,
          log_level: log_level,
          users_file: users_file,
          bootstrap_username: bootstrap_username,
          bootstrap_password: bootstrap_password,
          bootstrap_config_revision: bootstrap_config_revision,
          integrator_reset_flag: integrator_reset_flag,
          harvest_state_list: harvest_state_list,
          harvest_poll_seconds: harvest_poll_seconds,
          harvest_mode: harvest_mode,
          harvest_manifest_file: harvest_manifest_file,
          harvest_max_states: harvest_max_states,
          use_https: use_https,
          tls_cert_file: tls_cert_file,
          tls_key_file: tls_key_file
        )
      when 'bridge_stop'
        @bridge&.stop
        @bridge = nil
      when 'bridge_reload'
        if @bridge
          bind_host, port, use_https, tls_cert_file, tls_key_file, log_directory, log_level, users_file, bootstrap_username, bootstrap_password, bootstrap_config_revision, integrator_reset_flag, harvest_state_list, harvest_poll_seconds, harvest_mode, harvest_manifest_file, harvest_max_states = parts
          @bridge.reload(
            bind_host: bind_host,
            port: port,
            log_directory: log_directory,
            log_level: log_level,
            users_file: users_file,
            bootstrap_username: bootstrap_username,
            bootstrap_password: bootstrap_password,
            bootstrap_config_revision: bootstrap_config_revision,
            integrator_reset_flag: integrator_reset_flag,
            harvest_state_list: harvest_state_list,
            harvest_poll_seconds: harvest_poll_seconds,
            harvest_mode: harvest_mode,
            harvest_manifest_file: harvest_manifest_file,
            harvest_max_states: harvest_max_states,
            use_https: use_https,
            tls_cert_file: tls_cert_file,
            tls_key_file: tls_key_file
          )
        end
      when 'event'
        event_type = parts.shift.to_s
        @bridge&.ingest(event_type, parts)
      else
        puts "sentinel_api,error,0.0.0.0,0,0,0,unknown_command:#{cmd}".gsub(',', ';')
        STDOUT.flush
      end
    rescue => e
      puts "sentinel_api,error,0.0.0.0,0,0,0,dispatch_exception:#{e.class}:#{e.message}".gsub(',', ';')
      STDOUT.flush
    end
  end
end

at_exit do
  begin
    SavantNetworkSentinelCleanRubiBridgeV40Pro.instance_variable_get(:@bridge)&.stop
  rescue
    nil
  end
end

def savant_network_sentinel_dispatch(command_string)
  SavantNetworkSentinelCleanRubiBridgeV40Pro.dispatch(command_string)
end
