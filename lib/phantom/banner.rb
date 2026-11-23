module Phantom
  # Crescent moon + D-MOON branding. The moon is plain ASCII (assets/logo.txt).
  module Banner
    PURPLE = '38;5;97'.freeze
    SILVER = '38;5;250'.freeze
    WHITE = '1;37'.freeze

    module_function

    def color?(io = $stdout)
      io.tty? && ENV['NO_COLOR'].to_s.empty?
    end

    def paint(code, text, io = $stdout)
      color?(io) ? "\e[#{code}m#{text}\e[0m" : text
    end

    def logo_lines
      File.read(File.join(Phantom::ROOT, 'assets', 'logo.txt')).lines.map(&:chomp)
    rescue SystemCallError
      ['D-MOON', 'PHANTOM', 'CYBERSECURITY INTELLIGENCE SUITE']
    end

    def render(io = $stdout, width = 40)
      logo_lines.map do |line|
        case line
        when 'D-MOON' then paint(WHITE, line.center(width), io)
        when 'PHANTOM' then paint(SILVER, line.center(width), io)
        when 'CYBERSECURITY INTELLIGENCE SUITE' then paint(PURPLE, line.center(width), io)
        else paint(PURPLE, line, io)
        end
      end.join("\n")
    end

    def show(io = $stdout)
      io.puts render(io)
      io.puts
    end
  end
end
