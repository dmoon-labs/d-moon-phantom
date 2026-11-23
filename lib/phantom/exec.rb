module Phantom
  # Runs a child process WITHOUT a shell: the command is always an argv array,
  # so untrusted input can never be interpreted as shell syntax.
  module Exec
    Result = Struct.new(:out, :err, :status, :timed_out, :missing)

    module_function

    def run(cmd, stdin_data: '', env: {}, timeout: 60)
      res = Result.new('', '', nil, false, false)
      argv = cmd.dup
      first = argv.shift
      begin
        Open3.popen3(env, [first, first], *argv) do |stdin, stdout, stderr, waiter|
          begin
            stdin.write(stdin_data)
          rescue Errno::EPIPE
            nil
          end
          stdin.close
          reader_out = Thread.new { stdout.read }
          reader_err = Thread.new { stderr.read }
          if waiter.join(timeout).nil?
            begin
              ::Process.kill('KILL', waiter.pid)
            rescue Errno::ESRCH
              nil
            end
            res.timed_out = true
            reader_out.kill
            reader_err.kill
          else
            res.out = reader_out.value.to_s
            res.err = reader_err.value.to_s
            res.status = waiter.value
          end
        end
      rescue Errno::ENOENT, Errno::EACCES
        res.missing = true
      end
      res
    end
  end
end
