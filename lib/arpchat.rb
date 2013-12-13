require 'bit-struct'
require 'pcaprub'
require 'msgpack'
require_relative 'ether_struct'
require_relative 'arp_struct'

CYCLE=60
CHATROOM_ADDR="224.0.0.251"

module ArpChat
  MESSAGE = 0x01 
  HEARTBEAT = 0x10

  @@pcap = Pcap.open_live("en0", 0xffff, false, 1)
  @@pcap.setfilter('arp')

  @@name = "anonymous"
  @@src = { :mac_addr => "10:6f:3f:34:21:5f",
            :ip_addr => "224.#{rand(255)}.#{rand(255)}.#{rand(255)}" }
  @@dst = { :mac_addr => "ff:ff:ff:ff:ff:ff", :ip_addr => CHATROOM_ADDR }

  class Peers
    @@peers = []
    class Peer
      attr_accessor :ip, :updated_at
      def initialize(*args)
        args = args.first
        args.each do |k, v|
          self.instance_variable_set("@#{k}".to_sym, v)
        end
      end
    end

    class << self
      def update(ip)
        if @@peers.select{|peer| peer.ip == ip} == []
          @@peers << Peer.new(:ip => ip, :updated_at => Time.now)
        else
          @@peers.select!{|peer| peer.ip != ip}
          @@peers << Peer.new(:ip => ip, :updated_at => Time.now)
        end
      end

      def leave
        time = Time.now
        @@peers.select!{|peer| (time - peer.updated_at) <= CYCLE}
      end
    end
  end

  class Receiver
    @@peers = []

    class << self
      def read(&block)
        buf = {}
        @@pcap.each_data do |a|
          src = a[0x1c,4].unpack("C4").join(".")
          dst = a[0x26,4].unpack("C4").join(".")
          next if src == @@src[:ip_addr]
          next unless dst == CHATROOM_ADDR
         
          begin
          case a[59]
            when "\1"
              begin
                buf[src] += a[42,17]
              rescue => e
                buf[src] = a[42,17]
              end
            when "\0"
              begin
                str = (buf[src] + a[42,18]).encode("ASCII-8BIT").unpack("A*").first
              rescue => e
                str = a[42,18].encode("ASCII-8BIT").unpack("A*").first
              end

              begin
                name, func, body = MessagePack.unpack(str)
                case func
                  when MESSAGE
                    Peers.update(src)
                    block.call(name, body)
                  when HEARTBEAT
                    Peers.update(src)
                end
              rescue => e
              end
              buf[src] = ""
          end
          rescue => e
            p e
          end
        end
      end
    end
  end

  class Sender
    class Error
      class BodyEmpty < StandardError; end
    end

    class << self
      def name(name)
        @@name = name
      end

      def send(func, body)
        raise Error::BodyEmpty if body.empty?
        self.split(func, body).each do |i|
          self.write(i)
        end
      end

      def ip_header
        EtherStruct.new(
          :type => 0x0806,
          :src_addr => @@src[:mac_addr],
          :dst_addr => @@dst[:mac_addr]
        )
      end

      def arp_header
        ArpStruct.new(
          :sender_mac_addr => @@src[:mac_addr],
          :sender_ip_addr => @@src[:ip_addr],
          :target_mac_addr => @@dst[:mac_addr],
          :target_ip_addr => @@dst[:ip_addr],
          :opcode => 0x01
        )
      end

      def split(func, body)
        body = [@@name, func, body].to_msgpack
        arr = []
        buf = ""

        body.split(//).each do |i|
          buf << i
          if buf.size == 17
            arr << buf + "\1"
            buf = ""
          end
        end
        arr << buf + "\0"*(18-buf.size)

        arr.map!{|a| a.encode("ASCII-8BIT")}
      end

      def write(body)
        arp = self.arp_header
        arp.body = body
        ip = self.ip_header
        ip.body = arp.to_s
        @@pcap.inject(ip.to_s)
      end

      def heartbeat
        Thread.new do
          loop do
            self.send(HEARTBEAT, 'heartbeat')
            sleep CYCLE
            Peers.leave
          end
        end
      end
    end
  end
end
