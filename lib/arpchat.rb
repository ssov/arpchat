require 'bit-struct'
require 'pcaprub'
require 'ether_struct'
require 'arp_struct'

class ArpChat
  @@name = "anonymous"
  @@pcap = Pcap.open_live("en0", 0xffff, false, 1)
  @@src = { :mac_addr => "10:6f:3f:34:21:5f", :ip_addr => "123.234.123.234" }
  @@dst = { :mac_addr => "ff:ff:ff:ff:ff:ff", :ip_addr => "123.234.123.234" }

  class Error
    class BodyEmpty < StandardError; end
  end

  def self.name(name)
    @@name = name
  end

  def self.send(body)
    raise Error::BodyEmpty if body.empty?
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

  def self.write(body)
    @arp = self.arp_header
    @arp.body = body
    @ip = self.ip_header
    @ip.body = @arp.to_s
    @@pcap.inject(@ip.to_s)
  end
end
