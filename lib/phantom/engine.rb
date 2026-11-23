module Phantom
  # Talks to the Python engine with JSON over stdin/stdout.
  module Engine
    module_function

    def base_env
      { 'PYTHONPATH' => Config.engine_dir, 'PHANTOM_HOME' => Config.home,
        'PYTHONDONTWRITEBYTECODE' => '1' }
    end

    def error_env(tool, code, message)
      { 'ok' => false, 'tool' => tool, 'error' => { 'code' => code, 'message' => message } }
    end

    def call(tool, params = {}, timeout: 60)
      res = Exec.run([Config.python, '-m', 'phantom_engine', 'run', tool],
                     stdin_data: JSON.generate(params), env: base_env, timeout: timeout)
      return error_env(tool, 'python_missing', "#{Config.python} not found; run 'phantom doctor'") if res.missing
      return error_env(tool, 'timeout', "engine exceeded #{timeout}s") if res.timed_out

      begin
        JSON.parse(res.out)
      rescue JSON::ParserError
        error_env(tool, 'engine_protocol', "engine returned invalid JSON: #{res.err.to_s[0, 200]}")
      end
    end

    def info(command)
      res = Exec.run([Config.python, '-m', 'phantom_engine', command], env: base_env, timeout: 30)
      return nil if res.missing || res.timed_out

      JSON.parse(res.out)
    rescue JSON::ParserError
      nil
    end

    def schemas
      @schemas ||= (info('list') || [])
    end

    def schema_for(name)
      schemas.find { |s| s['name'] == name || s['id'] == name }
    end
  end
end
