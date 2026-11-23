module Phantom
  # Optional Rust core (core/). Used for fast URL/hostname validation. When the
  # binary has not been built the Python engine is used and this is reported.
  module Core
    module_function

    def available?
      File.executable?(Config.core_bin)
    end

    def call(payload, timeout: 10)
      return nil unless available?

      res = Exec.run([Config.core_bin], stdin_data: JSON.generate(payload), timeout: timeout)
      return nil if res.missing || res.timed_out || res.status.nil? || !res.status.success?

      JSON.parse(res.out)
    rescue JSON::ParserError
      nil
    end

    def normalize_url(url)
      call({ 'op' => 'normalize_url', 'url' => url })
    end

    def validate_hostname(host)
      call({ 'op' => 'validate_hostname', 'host' => host })
    end
  end
end
