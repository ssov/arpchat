require './lib/arpchat.rb'

Thread.new do
  ArpChat::Receiver.read do |body|
    puts body.chomp
  end
end

loop do
  str = gets.chomp
  ArpChat::Sender.send(str)
end
