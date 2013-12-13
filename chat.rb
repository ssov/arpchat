require_relative 'lib/arpchat.rb'

include ArpChat

configure do |config|
  config.receiveMessage = Proc.new {|src, name, body|
    puts "#{name}(#{src}) > #{body}"
  }

  config.joinPeer = Proc.new {|src|
    puts "#{src} has joined."
  }

  config.leftPeer = Proc.new {|peer|
    puts "#{peer.ip} has left. (last updated: #{peer.updated_at})"
  }
end
setup

loop do
  str = gets.chomp
  Sender.send(MESSAGE, str)
end
