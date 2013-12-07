require './lib/arpchat.rb'

Thread.new do
  ArpChat::Receiver.read do |sender, body|
    puts "#{sender} > #{body}"
  end
end

loop do
  str = gets.chomp
  ArpChat::Sender.send(str)
end
