require './lib/arpchat.rb'

ArpChat::Receiver.read do |packet|
  p packet.data
end
