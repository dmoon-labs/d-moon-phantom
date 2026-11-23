module Phantom
  # Moon art + D-MOON branding, read from assets/logo.txt.
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
      File.read(File.join(Phantom::ROOT, 'assets', 'logo.txt'), encoding: 'UTF-8').lines.map(&:chomp)
    rescue SystemCallError
      ['D-MOON', 'PHANTOM', 'CYBERSECURITY INTELLIGENCE SUITE']
    end

    # The moon is Unicode braille art; D-MOON and PHANTOM sit beside it on the
    # same lines, the subtitle below. Colors are applied per segment.
    def render(io = $stdout)
      logo_lines.map do |line|
        match = line.match(/\A(.*?)(D-MOON|PHANTOM)\z/)
        if match
          word_color = match[2] == 'D-MOON' ? WHITE : SILVER
          paint(PURPLE, match[1], io) + paint(word_color, match[2], io)
        else
          paint(PURPLE, line, io)
        end
      end.join("\n")
    end

    def show(io = $stdout)
      io.puts render(io)
      io.puts
    end
  end
end
