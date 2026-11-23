module Phantom
  # Runtime configuration. Everything can be overridden by environment
  # variables so the suite works from any Termux or Linux layout.
  module Config
    module_function

    def home
      dir = ENV['PHANTOM_HOME'] || File.join(Dir.home, '.d-moon')
      FileUtils.mkdir_p(dir)
      dir
    end

    def python
      ENV['PHANTOM_PYTHON'] || 'python3'
    end

    def engine_dir
      File.join(Phantom::ROOT, 'engine')
    end

    def core_bin
      ENV['PHANTOM_CORE'] || File.join(Phantom::ROOT, 'core', 'target', 'release', 'phantom-core')
    end

    def settings_path
      File.join(home, 'config.json')
    end

    def settings
      data = JSON.parse(File.read(settings_path))
      data.is_a?(Hash) ? data : {}
    rescue SystemCallError, JSON::ParserError
      {}
    end

    def save_setting(key, value)
      data = settings
      data[key] = value
      tmp = "#{settings_path}.tmp"
      File.write(tmp, JSON.pretty_generate(data))
      File.rename(tmp, settings_path)
    end

    def termux?
      ENV['PREFIX'].to_s.include?('com.termux')
    end
  end
end
