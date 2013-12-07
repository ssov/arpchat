require 'bit-struct'
require 'pcaprub'
require_relative 'ether_struct'
require_relative 'arp_struct'

module ArpChatModule
  @@pcap = Pcap.open_live("en0", 0xffff, false, 1)
  @@name = "anonymous"
  @@src = { :mac_addr => "10:6f:3f:34:21:5f", :ip_addr => "224.#{rand(255)}.#{rand(255)}.#{rand(255)}" }
  @@dst = { :mac_addr => "ff:ff:ff:ff:ff:ff", :ip_addr => "224.0.0.251" }
end

class ArpChat; end

class ArpChat::Receiver
  include ArpChatModule
  @@pcap.setfilter('arp')

  def self.read(&block)
    buf = ""
    @@pcap.each_data do |a|
      sender = a[0x1c,4].unpack("C4").join(".")
      case a[59]
        when "\1"
          buf << a[42,17]
        when "\0"
          str = (buf+a[42,18]).encode("ASCII-8BIT").unpack("A*").first
          unless str.size%2 == 0
            str << "\0"
          end
          str = str.unpack("S*").pack("U*")
          block.call(sender, str)
          buf = ""
      end
    end
  end
end

class ArpChat::Sender
  include ArpChatModule

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

    @arr.map!{|a| a.encode("ASCII-8BIT")}
  end

  def self.write(body)
    @arp = self.arp_header
    @arp.body = body
    @ip = self.ip_header
    @ip.body = @arp.to_s
    @@pcap.inject(@ip.to_s)
  end
end
