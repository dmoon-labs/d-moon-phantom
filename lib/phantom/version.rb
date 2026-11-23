module Phantom
  ROOT = File.expand_path('../../..', File.realpath(__FILE__))
  VERSION = File.read(File.join(ROOT, 'VERSION')).strip
end
