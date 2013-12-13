require './lib/arpchat.rb'

include ArpChat

Thread.new do
  Receiver.read do |sender, body|
    puts "#{sender} > #{body}"
  end
end

Sender.heartbeat

loop do
  str = gets.chomp
  Sender.send(MESSAGE, str)
end
