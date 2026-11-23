require 'io/console'

module Phantom
  # Banner = moon art (assets/moons/<id>.txt) + D-MOON / PHANTOM + subtitle.
  # The user picks the moon with phantom art; the choice is stored in
  # $PHANTOM_HOME/config.json. PHANTOM_MOON=<id> overrides it for one run.
  module Banner
    PURPLE = '38;5;97'.freeze
    SILVER = '38;5;250'.freeze
    WHITE = '1;37'.freeze
    TITLE = 'D-MOON'.freeze
    NAME = 'PHANTOM'.freeze
    SUBTITLE = 'CYBERSECURITY INTELLIGENCE SUITE'.freeze
    DEFAULT_MOON = '0'.freeze
    GAP = 3

    module_function

    def color?(io = $stdout)
      io.tty? && ENV['NO_COLOR'].to_s.empty?
    end

    def paint(code, text, io = $stdout)
      color?(io) ? "\e[#{code}m#{text}\e[0m" : text
    end

    def moons_dir
      File.join(Phantom::ROOT, 'assets', 'moons')
    end

    def moon_ids
      Dir.children(moons_dir).select { |f| f.end_with?('.txt') }
         .map { |f| f.sub(/\.txt\z/, '') }.sort_by(&:to_i)
    rescue SystemCallError
      []
    end

    def moon_name(id)
      id == DEFAULT_MOON ? 'Classic (default)' : "Moon #{id}"
    end

    def current_moon
      id = ENV['PHANTOM_MOON'] || Config.settings['moon']
      moon_ids.include?(id.to_s) ? id.to_s : DEFAULT_MOON
    end

    def moon_lines(id)
      File.read(File.join(moons_dir, "#{id}.txt"), encoding: 'UTF-8').lines.map(&:chomp)
    rescue SystemCallError
      []
    end

    def moon_size(id)
      lines = moon_lines(id)
      [lines.map(&:length).max.to_i, lines.length]
    end

    def columns(io = $stdout)
      n = 0
      if io.tty?
        begin
          n = io.winsize[1].to_i
        rescue StandardError
          n = 0
        end
      end
      n = ENV['COLUMNS'].to_i if n.zero?
      n.zero? ? 80 : n
    end

    # Rows are [art_text, label_text_or_nil, label_color].
    def compose(art, cols)
      width = art.map(&:length).max.to_i
      rows = []
      if !art.empty? && width + GAP + NAME.length <= cols
        mid = art.length / 2
        art.each_with_index do |line, i|
          if i == mid - 1
            rows << [line.ljust(width) + (' ' * GAP), TITLE, WHITE]
          elsif i == mid
            rows << [line.ljust(width) + (' ' * GAP), NAME, SILVER]
          else
            rows << [line, nil, nil]
          end
        end
        rows << ['', nil, nil]
        rows << [' ' * [(width - SUBTITLE.length) / 2, 0].max, SUBTITLE, PURPLE]
      else
        pad = ' ' * [(width - NAME.length) / 2, 0].max
        art.each { |line| rows << [line, nil, nil] }
        rows << ['', nil, nil]
        rows << [pad, TITLE, WHITE]
        rows << [pad, NAME, SILVER]
        rows << [' ' * [(width - SUBTITLE.length) / 2, 0].max, SUBTITLE, PURPLE]
      end
      rows
    end

    def render(io = $stdout, moon: nil)
      id = moon || current_moon
      compose(moon_lines(id), columns(io)).map do |art, label, color|
        paint(PURPLE, art, io) + (label ? paint(color, label, io) : '')
      end.join("\n")
    end

    def show(io = $stdout, moon: nil)
      io.puts render(io, moon: moon)
      io.puts
    end
  end
end
