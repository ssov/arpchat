require_relative 'lib/arpchat.rb'

include ArpChat

configure do |config|
  config.receiveMessage = Proc.new {|peer, body|
    puts "#{peer.name}(#{peer.ip}) > #{body}"
  }

  config.joinPeer = Proc.new {|peer|
    puts "#{peer.ip} has joined."
  }

  config.leavePeer = Proc.new {|peer|
    puts "#{peer.ip} has left. (last updated: #{peer.updated_at})"
  }
end
setup

loop do
  begin
    str = gets.chomp
    Sender.message(str)
  rescue Interrupt
    Sender.leave
    break
  end
end
