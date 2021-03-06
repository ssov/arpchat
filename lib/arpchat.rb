require 'bit-struct'
require 'pcaprub'
require 'msgpack'

require_relative 'structs/ether_struct'
require_relative 'structs/arp_struct'

require_relative 'arpchat/callback'
require_relative 'arpchat/receiver'
require_relative 'arpchat/sender'
require_relative 'arpchat/peers'
require_relative 'arpchat/sender'

CYCLE=60
CHATROOM_ADDR="224.0.0.251"

module ArpChat
  MESSAGE = 0x01 
  HEARTBEAT = 0x10
  JOIN = 0x20
  LEAVE = 0x21
  MYNAME = 0x30
  YOURNAME = 0x31

  ONLY = 0x04
  START = 0x01
  FRAGMENT = 0x02
  LAST = 0x03

  @@pcap = Pcap.open_live("en0", 0xffff, false, 1)
  @@pcap.setfilter('arp')

  @@name = "anonymous"
  @@src = { :mac_addr => "10:6f:3f:" + 3.times.map{rand(255).to_s(16)}.join(":"),
            :ip_addr => "224." + 3.times.map{rand(255)}.join(".") }
  @@dst = { :mac_addr => "ff:ff:ff:ff:ff:ff", :ip_addr => CHATROOM_ADDR }

  def setup
    Sender.join
    Thread.new do 
      loop { Receiver.read }
    end

    Thread.new do 
      loop do
        Sender.send(HEARTBEAT, 'hb')
        sleep CYCLE
        Peers.exist?
      end
    end
  end

  def configure(&block)
    @@proc = Callback.new
    block.call(@@proc)
  end
end
