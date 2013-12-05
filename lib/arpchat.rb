require 'bit-struct'
require 'pcaprub'
require_relative 'ether_struct'
require_relative 'arp_struct'

module ArpChatModule
  @@pcap = Pcap.open_live("en0", 0xffff, false, 1)
end

class ArpChat; end

class ArpChat::Receiver
  include ArpChatModule
  @@pcap.setfilter('arp')

  def self.read(&block)
    @@pcap.each_packet do |packet|
      block.call(packet)
    end
  end
end

class ArpChat::Sender
  include ArpChatModule

  @@name = "anonymous"
  @@src = { :mac_addr => "10:6f:3f:34:21:5f", :ip_addr => "224.0.0.250" }
  @@dst = { :mac_addr => "ff:ff:ff:ff:ff:ff", :ip_addr => "224.0.0.251" }

  class Error
    class BodyEmpty < StandardError; end
  end

  def self.name(name)
    @@name = name
  end

  def self.send(body)
    raise Error::BodyEmpty if body.empty?
    self.split(body).each do |i|
      self.write(i)
    end
  end

  def self.ip_header
    EtherStruct.new(:type => 0x0806, :src_addr => @@src[:mac_addr], :dst_addr => @@dst[:mac_addr])
  end

  def self.arp_header
    ArpStruct.new(
      :sender_mac_addr => @@src[:mac_addr],
      :sender_ip_addr => @@src[:ip_addr],
      :target_mac_addr => @@dst[:mac_addr],
      :target_ip_addr => @@dst[:ip_addr],
      :opcode => 0x01
    )
  end

  def self.split(body)
    @body = body.unpack("U*").pack("S*")
    @arr = []
    buf = ""
    @body.split(//).each do |i|
      buf << i
      if buf.size == 17
        @arr << buf + "\1"
        buf = ""
      end
    end
    @arr << buf + "\0"*(18-buf.size)
  end

  def self.write(body)
    @arp = self.arp_header
    @arp.body = body
    @ip = self.ip_header
    @ip.body = @arp.to_s
    @@pcap.inject(@ip.to_s)
  end
end
