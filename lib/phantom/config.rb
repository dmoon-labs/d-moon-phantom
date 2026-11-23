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

    def termux?
      ENV['PREFIX'].to_s.include?('com.termux')
    end
  end
end
