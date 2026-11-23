module Phantom
  # Workflows are ordered lists of registered tools run against one target.
  module Workflows
    URL_SCAN = %w[
      url.structure_check url.ip_host_detect url.userinfo_trick
      url.encoding_obfuscation url.length_entropy url.shortener_detect
    ].freeze

    PHISHING_SCAN = %w[
      url.phishing_score url.redirect_params url.idn_homograph url.brand_impersonation
    ].freeze

    DOMAIN_ANALYSIS = %w[
      domain.validate domain.split domain.lexical_profile domain.dga_score
      domain.tld_profile domain.risk_score
    ].freeze

    FILE_BASE = %w[
      file.hash file.type_detect file.extension_check file.entropy file.strings file.ioc_extract
    ].freeze

    module_function

    def run_steps(tools, key, value, timeout)
      tools.map { |tool| Engine.call(tool, { key => value }, timeout: timeout) }
    end

    def file_steps(type_name, path)
      extra = []
      case type_name
      when 'Windows PE executable' then extra << 'file.pe_analyze'
      when 'ELF executable/library' then extra << 'file.elf_analyze'
      when 'ZIP container', 'Java JAR', 'Android APK' then extra << 'file.archive_inspect'
      when 'PDF document', 'RTF document', 'OLE2 (legacy Office)' then extra << 'file.document_indicators'
      when 'Office Open XML' then extra += %w[file.document_indicators file.archive_inspect]
      end
      extra << 'file.archive_inspect' if path =~ /\.(tar|tgz|tar\.gz)\z/i && !extra.include?('file.archive_inspect')
      extra
    end

    def file_analysis(path, timeout)
      envs = run_steps(FILE_BASE, 'path', path, timeout)
      type_env = envs[1]
      type_name = type_env['ok'] ? type_env['result']['type'] : nil
      file_steps(type_name, path).each do |tool|
        envs << Engine.call(tool, { 'path' => path }, timeout: timeout)
      end
      envs
    end

    def dns_params(name, rtype, opts)
      params = { 'name' => name, 'rtype' => rtype, 'timeout' => opts[:timeout], 'authorized' => true }
      params['server'] = opts[:dns_server] if opts[:dns_server]
      params
    end

    def dns_analysis(domain, opts)
      envs = []
      answers = {}
      %w[A AAAA MX NS TXT CAA].each do |rtype|
        env = Engine.call('dns.query', dns_params(domain, rtype, opts), timeout: opts[:timeout] + 15)
        envs << env
        answers[rtype] = env['ok'] ? env['result']['answers'].select { |a| a['type'] == rtype } : []
      end
      dmarc = Engine.call('dns.query', dns_params("_dmarc.#{domain}", 'TXT', opts), timeout: opts[:timeout] + 15)
      envs << dmarc
      dmarc_txt = dmarc['ok'] ? dmarc['result']['answers'].select { |a| a['type'] == 'TXT' } : []

      spf = answers['TXT'].find { |a| a['data'].to_s.downcase.start_with?('v=spf1') }
      envs << Engine.call('dns.spf_analyze', { 'record' => spf['data'] }) if spf
      dm = dmarc_txt.find { |a| a['data'].to_s.upcase.start_with?('V=DMARC1') }
      envs << Engine.call('dns.dmarc_analyze', { 'record' => dm['data'] }) if dm
      envs << Engine.call('dns.mx_analyze', { 'records' => answers['MX'].map { |a| a['data'] } })
      envs << Engine.call('dns.caa_analyze', { 'records' => answers['CAA'].map { |a| a['data'] } })
      all = answers.values.flatten
      envs << Engine.call('dns.ttl_analyze', { 'records' => all }) unless all.empty?
      envs
    end

    def ssl_analysis(host, port, opts)
      envs = []
      live = Engine.call('tls.live_handshake',
                         { 'host' => host, 'port' => port, 'timeout' => opts[:timeout], 'authorized' => true },
                         timeout: opts[:timeout] + 20)
      envs << live
      return envs unless live['ok']

      pem = live['result']['pem']
      envs << Engine.call('tls.hostname_match', { 'pem' => pem, 'hostname' => host })
      %w[tls.sigalg_check tls.key_strength tls.lifetime_check tls.expiry_check].each do |tool|
        envs << Engine.call(tool, { 'pem' => pem })
      end
      envs
    end

    def header_analysis(url, opts)
      fetch = Engine.call('http.fetch',
                          { 'url' => url, 'follow' => true, 'timeout' => opts[:timeout], 'authorized' => true },
                          timeout: opts[:timeout] * 5 + 20)
      envs = [fetch]
      return envs unless fetch['ok']

      https = fetch['result']['final_url'].to_s.downcase.start_with?('https://')
      envs << Engine.call('http.headers_audit',
                          { 'headers' => fetch['result']['headers_text'], 'https' => https })
      envs
    end
  end
end
