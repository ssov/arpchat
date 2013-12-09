require './lib/arpchat.rb'

include ArpChatCore

Thread.new do
  ArpChat::Receiver.read do |sender, body|
    puts "#{sender} > #{body}"
  end
end

ArpChat::Receiver.heartbeat

loop do
  str = gets.chomp
  ArpChat::Sender.send(MESSAGE, str)
end
