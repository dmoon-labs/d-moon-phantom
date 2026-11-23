module Phantom
  class UsageError < StandardError; end

  # Command routing for the phantom executable.
  # Exit codes: 0 ok, 1 tool/runtime failure, 2 usage error, 3 --fail-on threshold hit.
  class CLI
    SEVERITIES = %w[info low medium high critical].freeze
    VALUE_FLAGS = %w[--timeout --dns-server --html --format --fail-on --category --params].freeze

    USAGE = <<~TXT.freeze
      Usage: phantom <command> [options]

      Scanning and analysis
        scan url <URL>               local URL checks (URL is never visited)
        scan phishing <URL>          phishing heuristics for a URL
        analyze domain <DOMAIN>      offline domain analysis
        analyze dns <DOMAIN>         live DNS + SPF/DMARC review   (--authorized)
        inspect ssl <HOST[:PORT]>    live TLS inspection           (--authorized)
        inspect headers <URL>        live HTTP header audit        (--authorized)
        file analyze <FILE>          local file inspection

      Tools and reports
        tools list [--category URL]  list the tool registry
        tools search <text>          search tools
        tools info <name>            show one tool's schema
        tools count                  implemented tool counts
        run <tool> key=value ...     run any single tool (value @file reads a file)
        report list                  saved reports
        report show <ID>             show a report (--format txt|json|html)

      Appearance
        art                          choose the moon ASCII art (menu)
        art list|preview N|set N     list, preview or select a moon

      System
        system status                versions, tool counts, verification status
        doctor                       environment diagnostics
        update                       upgrade a git-based install

      Options
        --authorized   confirm you own or may test the target (required for network commands)
        --offline      refuse every network operation
        --json         machine-readable output (banner goes to stderr)
        --no-save      do not store the report
        --html FILE    also write an HTML report
        --fail-on SEV  exit 3 if a finding is at least SEV (info|low|medium|high|critical)
        --timeout N    network timeout in seconds (1-15, default 5)
        --dns-server IP  resolver for analyze dns (default 1.1.1.1)
        --no-color     disable colors
        -h, --help     this help      -V, --version   version
    TXT

    def initialize
      @opts = { save: true, timeout: 5 }
    end

    def run(argv)
      pos = parse_flags(argv)
      return print_version if @opts[:version]

      banner_io = @opts[:json] ? $stderr : $stdout
      Banner.show(banner_io) unless @opts[:quiet]
      if @opts[:help] || pos.empty? || pos[0] == 'help'
        puts USAGE
        return 0
      end
      dispatch(pos)
    rescue UsageError => e
      warn "phantom: #{e.message}"
      2
    rescue Interrupt
      warn 'interrupted'
      130
    end

    private

    # ------------------------------------------------------------ parsing
    def parse_flags(argv)
      pos = []
      i = 0
      while i < argv.length
        arg = argv[i]
        case arg
        when '--help', '-h' then @opts[:help] = true
        when '--version', '-V' then @opts[:version] = true
        when '--json' then @opts[:json] = true
        when '--authorized' then @opts[:authorized] = true
        when '--offline' then @opts[:offline] = true
        when '--no-save' then @opts[:save] = false
        when '--no-color' then ENV['NO_COLOR'] = '1'
        when *VALUE_FLAGS
          i += 1
          raise UsageError, "#{arg} needs a value" if i >= argv.length

          @opts[arg.sub('--', '').tr('-', '_').to_sym] = argv[i]
        else
          raise UsageError, "unknown option #{arg}" if arg.start_with?('--')

          pos << arg
        end
        i += 1
      end
      normalize_opts
      pos
    end

    def normalize_opts
      if @opts[:timeout].is_a?(String)
        raise UsageError, '--timeout must be an integer' unless @opts[:timeout] =~ /\A\d+\z/

        @opts[:timeout] = @opts[:timeout].to_i
      end
      @opts[:timeout] = [[@opts[:timeout], 1].max, 15].min
      if @opts[:fail_on] && !SEVERITIES.include?(@opts[:fail_on])
        raise UsageError, "--fail-on must be one of #{SEVERITIES.join(', ')}"
      end
      return unless @opts[:dns_server] && @opts[:dns_server] !~ /\A[0-9a-fA-F:.]+\z/

      raise UsageError, '--dns-server must be an IP address'
    end

    def print_version
      puts "D-MOON PHANTOM #{Phantom::VERSION}"
      0
    end

    def dispatch(pos)
      args = pos[1..-1]
      case pos[0]
      when 'tools' then cmd_tools(args)
      when 'run' then cmd_run(args)
      when 'scan' then cmd_scan(args)
      when 'analyze' then cmd_analyze(args)
      when 'inspect' then cmd_inspect(args)
      when 'file' then cmd_file(args)
      when 'report' then cmd_report(args)
      when 'art' then cmd_art(args)
      when 'system' then cmd_system(args)
      when 'doctor' then cmd_doctor
      when 'update' then cmd_update
      else raise UsageError, "unknown command '#{pos[0]}'. Run 'phantom --help'."
      end
    end

    def need(args, index, what)
      value = args[index]
      raise UsageError, "missing #{what}" if value.nil? || value.empty?

      value
    end

    def require_network!
      raise UsageError, 'this command is network-based but --offline was given' if @opts[:offline]
      return if @opts[:authorized]

      raise UsageError, 'network command: add --authorized to confirm you own or are permitted to test the target'
    end

    # ------------------------------------------------------------ tools
    def cmd_tools(args)
      case args[0]
      when 'list' then tools_list
      when 'search' then tools_search(args[1..-1].join(' '))
      when 'info' then tools_info(need(args, 1, 'tool name'))
      when 'count' then tools_count
      else raise UsageError, 'usage: phantom tools list|search|info|count'
      end
    end

    def schemas_or_fail
      list = Engine.schemas
      if list.empty?
        warn "engine unavailable. Run 'phantom doctor'."
        return nil
      end
      list
    end

    def print_tools(list)
      if @opts[:json]
        puts JSON.pretty_generate(list)
        return 0
      end
      list.each do |s|
        puts "#{s['id']}  #{s['name']}  [#{s['permission']}]"
        puts "    #{s['description'][0, 100]}"
      end
      puts "#{list.length} tool(s)"
      0
    end

    def tools_list
      list = schemas_or_fail or return 1
      if @opts[:category]
        key = @opts[:category].downcase
        list = list.select { |s| s['id'].downcase.start_with?(key) || s['category'].downcase.include?(key) }
      end
      print_tools(list)
    end

    def tools_search(term)
      raise UsageError, 'missing search text' if term.strip.empty?

      list = schemas_or_fail or return 1
      key = term.downcase
      hits = list.select { |s| [s['name'], s['description'], s['category']].join(' ').downcase.include?(key) }
      print_tools(hits)
    end

    def tools_info(name)
      schema = Engine.schema_for(name)
      raise UsageError, "no such tool: #{name}" unless schema

      if @opts[:json]
        puts JSON.pretty_generate(schema)
        return 0
      end
      puts "#{schema['id']}  #{schema['name']}  (#{schema['category']})"
      puts schema['description']
      puts "language: #{schema['language']}   permission: #{schema['permission']}"
      puts 'inputs:'
      schema['input_schema'].each do |k, v|
        puts "  #{k}: #{v['type']}#{v['required'] ? ' (required)' : " (default #{v['default'].inspect})"}"
      end
      puts "outputs: #{schema['output_schema'].join(', ')}"
      0
    end

    def tools_count
      counts = Engine.info('counts')
      unless counts
        warn "engine unavailable. Run 'phantom doctor'."
        return 1
      end
      if @opts[:json]
        puts JSON.pretty_generate(counts)
      else
        puts "implemented tools: #{counts['implemented']}"
        counts['per_category'].each { |k, v| puts "  #{k}: #{v}" }
      end
      0
    end

    # ------------------------------------------------------------ run
    def convert(type, value, key)
      case type
      when 'int' then Integer(value)
      when 'float' then Float(value)
      when 'bool' then %w[true 1 yes].include?(value.downcase)
      when 'list' then value.split(',').map(&:strip)
      when 'dict' then JSON.parse(value)
      else
        if value.start_with?('@')
          path = value[1..-1]
          raise UsageError, "#{key}: cannot read #{path}" unless File.file?(path) && File.size(path) <= 8 * 1024 * 1024

          File.read(path)
        else
          value
        end
      end
    rescue ArgumentError, JSON::ParserError
      raise UsageError, "#{key}: invalid #{type} value"
    end

    def cmd_run(args)
      name = need(args, 0, 'tool name')
      schema = Engine.schema_for(name)
      raise UsageError, "no such tool: #{name} (see 'phantom tools list')" unless schema

      params = {}
      if @opts[:params]
        begin
          params = JSON.parse(@opts[:params])
        rescue JSON::ParserError
          raise UsageError, '--params must be valid JSON'
        end
      end
      args[1..-1].each do |pair|
        key, value = pair.split('=', 2)
        raise UsageError, "expected key=value, got '#{pair}'" if value.nil?

        spec = schema['input_schema'][key]
        raise UsageError, "tool #{name} has no parameter '#{key}'" unless spec

        params[key] = convert(spec['type'], value, key)
      end
      if schema['permission'] == 'network'
        require_network!
        params['authorized'] = true
      end
      env = Engine.call(schema['name'], params, timeout: 90)
      if @opts[:json]
        puts JSON.pretty_generate(env)
      else
        print_envelope(env)
      end
      env['ok'] ? 0 : 1
    end

    def print_envelope(env)
      unless env['ok']
        warn "error [#{env['error']['code']}]: #{env['error']['message']}"
        return
      end
      puts "#{env['tool_id']} #{env['tool']}"
      puts JSON.pretty_generate(env['result'])
      risk = env['risk']
      puts "risk: #{risk['score']}/100 (#{risk['label']}) - #{risk['basis']}" if risk
    end

    # ------------------------------------------------------------ workflows
    def cmd_scan(args)
      kind = need(args, 0, "scan type (url|phishing)")
      url = need(args, 1, 'URL')
      raise UsageError, 'usage: phantom scan url|phishing <URL>' unless %w[url phishing].include?(kind)

      core_note(url)
      tools = kind == 'url' ? Workflows::URL_SCAN : Workflows::PHISHING_SCAN
      envs = Workflows.run_steps(tools, 'url', url, 60)
      finish("#{kind} scan", url, envs)
    end

    def core_note(url)
      return if @opts[:json]

      core = Core.normalize_url(url)
      if core
        status = core['valid'] ? "normalized -> #{core['normalized']}" : "rejected: #{core['error']}"
        puts "rust core: #{status}"
      else
        puts 'rust core: not built, using the Python implementation'
      end
    end

    def cmd_analyze(args)
      kind = need(args, 0, 'analysis type (domain|dns)')
      target = need(args, 1, 'domain')
      case kind
      when 'domain'
        finish('domain analysis', target, Workflows.run_steps(Workflows::DOMAIN_ANALYSIS, 'domain', target, 60))
      when 'dns'
        require_network!
        finish('dns analysis', target, Workflows.dns_analysis(target, @opts))
      else raise UsageError, 'usage: phantom analyze domain|dns <DOMAIN>'
      end
    end

    def cmd_inspect(args)
      kind = need(args, 0, 'inspection type (ssl|headers)')
      target = need(args, 1, 'target')
      case kind
      when 'ssl'
        require_network!
        host, port = target.split(':', 2)
        port = port ? Integer(port) : 443
        finish('tls inspection', target, Workflows.ssl_analysis(host, port, @opts))
      when 'headers'
        require_network!
        finish('http header audit', target, Workflows.header_analysis(target, @opts))
      else raise UsageError, 'usage: phantom inspect ssl|headers <target>'
      end
    rescue ArgumentError
      raise UsageError, 'invalid port'
    end

    def cmd_file(args)
      raise UsageError, 'usage: phantom file analyze <FILE>' unless args[0] == 'analyze'

      path = need(args, 1, 'file path')
      raise UsageError, "no such file: #{path}" unless File.file?(path)

      finish('file analysis', path, Workflows.file_analysis(File.expand_path(path), 120))
    end

    def finish(title, target, envs)
      built = Engine.call('report.build',
                          { 'title' => title, 'target' => target, 'results' => envs, 'save' => @opts[:save] })
      unless built['ok']
        warn "could not build report: #{built['error']['message']}"
        return 1
      end
      report = built['result']
      write_html(report) if @opts[:html]
      if @opts[:json]
        puts JSON.pretty_generate(report)
      else
        text = Engine.call('report.render_txt', { 'report' => report })
        puts colorize(text['ok'] ? text['result']['text'] : JSON.pretty_generate(report))
        puts "Report saved: #{report['saved_to']}" if report['saved_to']
      end
      return 1 if report['summary']['tools_run'].to_i.zero?

      threshold_hit?(report) ? 3 : 0
    end

    def write_html(report)
      html = Engine.call('report.render_html', { 'report' => report })
      if html['ok']
        File.write(@opts[:html], html['result']['html'])
        warn "HTML report written to #{@opts[:html]}"
      else
        warn "HTML report failed: #{html['error']['message']}"
      end
    end

    def threshold_hit?(report)
      return false unless @opts[:fail_on]

      limit = SEVERITIES.index(@opts[:fail_on])
      report['findings'].any? { |f| SEVERITIES.index(f['severity']).to_i >= limit }
    end

    def colorize(text)
      return text unless Banner.color?

      text.gsub(/^\[(CRITICAL|HIGH)\]/) { "\e[1;31m#{Regexp.last_match(0)}\e[0m" }
          .gsub(/^\[MEDIUM\]/) { "\e[33m#{Regexp.last_match(0)}\e[0m" }
    end

    # ------------------------------------------------------------ reports
    def cmd_report(args)
      case args[0]
      when 'list'
        env = Engine.call('report.list', { 'limit' => 50 })
        return fail_env(env) unless env['ok']

        if @opts[:json]
          puts JSON.pretty_generate(env['result'])
        else
          env['result']['reports'].each do |r|
            s = r['summary']
            puts "#{r['id']}  #{r['title']}  #{r['target']}  crit=#{s['critical']} high=#{s['high']} med=#{s['medium']}"
          end
          puts "#{env['result']['total']} report(s)"
        end
        0
      when 'show'
        show_report(need(args, 1, 'report ID'))
      else raise UsageError, 'usage: phantom report list|show <ID>'
      end
    end

    def show_report(id)
      fmt = @opts[:format] || 'txt'
      raise UsageError, '--format must be txt, json or html' unless %w[txt json html].include?(fmt)

      env = Engine.call('report.show', { 'id' => id, 'format' => fmt })
      return fail_env(env) unless env['ok']

      case fmt
      when 'json' then puts JSON.pretty_generate(env['result']['report'])
      when 'html'
        if @opts[:html]
          File.write(@opts[:html], env['result']['rendered'])
          warn "HTML report written to #{@opts[:html]}"
        else
          puts env['result']['rendered']
        end
      else puts colorize(env['result']['rendered'])
      end
      0
    end

    def fail_env(env)
      warn "error [#{env['error']['code']}]: #{env['error']['message']}"
      1
    end

    # ------------------------------------------------------------ art menu
    def print_moon_list
      current = Banner.current_moon
      cols = Banner.columns
      Banner.moon_ids.each do |id|
        width, height = Banner.moon_size(id)
        marker = id == current ? '*' : ' '
        fit = width <= cols ? '' : "  (needs #{width} columns; zoom out)"
        puts format('%s %-2s %-18s %2dx%-2d%s', marker, id, Banner.moon_name(id), width, height, fit)
      end
      puts "* = selected. Screen width: #{cols} columns."
    end

    def valid_moon!(id)
      raise UsageError, 'missing moon number' if id.nil?
      raise UsageError, "no such moon '#{id}' (see 'phantom art list')" unless Banner.moon_ids.include?(id)

      id
    end

    def select_moon(id)
      Config.save_setting('moon', id)
      puts "Moon #{id} selected. Preview:"
      puts
      Banner.show($stdout, moon: id)
    end

    def cmd_art(args)
      case args[0]
      when nil then art_menu
      when 'list' then print_moon_list
      when 'preview'
        Banner.show($stdout, moon: valid_moon!(args[1]))
      when 'set'
        select_moon(valid_moon!(args[1]))
      else raise UsageError, 'usage: phantom art [list | preview N | set N]'
      end
      0
    end

    def art_menu
      print_moon_list
      unless $stdin.tty?
        puts "Choose with: phantom art set <number>"
        return
      end
      loop do
        print "\nNumber to select, p<number> to preview, Enter to quit: "
        $stdout.flush
        answer = $stdin.gets
        break if answer.nil? || answer.strip.empty? || answer.strip.downcase == 'q'

        answer = answer.strip
        if answer =~ /\Ap\s*(\d+)\z/i
          id = Regexp.last_match(1)
          Banner.moon_ids.include?(id) ? Banner.show($stdout, moon: id) : puts("No such moon: #{id}")
        elsif Banner.moon_ids.include?(answer)
          select_moon(answer)
          break
        else
          puts "Not a valid choice: #{answer}"
        end
      end
    end

    # ------------------------------------------------------------ system
    def cmd_system(args)
      raise UsageError, 'usage: phantom system status' unless args[0] == 'status'

      counts = Engine.info('counts')
      status_file = File.join(Phantom::ROOT, 'registry_status.json')
      verified = File.file?(status_file) ? (JSON.parse(File.read(status_file)) rescue nil) : nil
      if @opts[:json]
        puts JSON.pretty_generate('version' => Phantom::VERSION, 'engine' => counts,
                                  'core_available' => Core.available?, 'home' => Config.home,
                                  'verification' => verified)
        return 0
      end
      puts "D-MOON PHANTOM #{Phantom::VERSION}"
      puts "engine:  #{counts ? "#{counts['implemented']} tools implemented" : 'UNAVAILABLE (run phantom doctor)'}"
      puts "core:    #{Core.available? ? 'Rust core built' : 'Rust core not built (Python fallback)'}"
      puts "home:    #{Config.home}"
      if verified
        puts "verified: implemented=#{verified['implemented']} tested=#{verified['tested']} " \
             "documented=#{verified['documented']} stable=#{verified['stable'] ? 'yes' : 'NO'}"
      else
        puts 'verified: not run yet (python3 tools/release_verify.py)'
      end
      counts ? 0 : 1
    end

    def cmd_doctor
      checks = []
      py = Exec.run([Config.python, '--version'], timeout: 10)
      if py.missing
        checks << ['python3', 'fail', "#{Config.python} not found (pkg install python)"]
      else
        ver = (py.out + py.err).strip
        ok = ver =~ /Python 3\.(\d+)/ && Regexp.last_match(1).to_i >= 8
        checks << ['python3', ok ? 'ok' : 'fail', ver.empty? ? 'unknown version' : ver]
      end
      checks << ['ruby', RUBY_VERSION >= '2.7' ? 'ok' : 'fail', "Ruby #{RUBY_VERSION}"]
      counts = Engine.info('counts')
      checks << ['engine', counts && counts['implemented'] >= 100 ? 'ok' : 'fail',
                 counts ? "#{counts['implemented']} tools" : 'cannot import phantom_engine']
      checks << ['rust core', Core.available? ? 'ok' : 'warn',
                 Core.available? ? Config.core_bin : 'optional: cd core && cargo build --release']
      checks << ['home dir', File.writable?(Config.home) ? 'ok' : 'fail', Config.home]
      checks << ['platform', 'ok', "#{RbConfig::CONFIG['host_cpu']} #{Config.termux? ? '(Termux)' : '(not Termux)'}"]
      checks << ['git', system_git_ok? ? 'ok' : 'warn', 'needed only for phantom update']
      bad = false
      checks.each do |name, level, detail|
        bad ||= level == 'fail'
        puts format('%-10s [%s] %s', name, level, detail)
      end
      bad ? 1 : 0
    end

    def system_git_ok?
      !Exec.run(['git', '--version'], timeout: 10).missing
    end

    def cmd_update
      unless File.directory?(File.join(Phantom::ROOT, '.git'))
        puts 'This install is not a git checkout.'
        puts 'Upgrade: download the new release archive, extract it over this directory,'
        puts "run ./install.sh, then 'phantom doctor'."
        return 0
      end
      res = Exec.run(['git', '-C', Phantom::ROOT, 'pull', '--ff-only'], timeout: 180)
      if res.missing
        warn 'git not found (pkg install git)'
        return 1
      end
      return fail_text('git pull timed out') if res.timed_out

      puts res.out
      warn res.err unless res.err.to_s.empty?
      return 1 unless res.status && res.status.success?

      puts "Updated. Rebuild the optional Rust core: (cd core && cargo build --release)"
      puts "Then verify: phantom doctor"
      0
    end

    def fail_text(message)
      warn message
      1
    end
  end
end
