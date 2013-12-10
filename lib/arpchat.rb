require 'bit-struct'
require 'pcaprub'
require 'msgpack'
require_relative 'ether_struct'
require_relative 'arp_struct'

CYCLE=60

module ArpChat
  @@pcap = Pcap.open_live("en0", 0xffff, false, 1)
  @@pcap.setfilter('arp')

  @@name = "anonymous"
  @@src = { :mac_addr => "10:6f:3f:34:21:5f",
            :ip_addr => "224.#{rand(255)}.#{rand(255)}.#{rand(255)}" }
  @@dst = { :mac_addr => "ff:ff:ff:ff:ff:ff", :ip_addr => "224.0.0.251" }

  MESSAGE = 0x01 
  HEARTBEAT = 0x10

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
        @time = Time.now
        @@peers.select{|peer| (@time - peer.updated_at) > CYCLE}.each do |peer|
          puts ">> leave #{peer.ip}"
        end
        @@peers.select!{|peer| (@time - peer.updated_at) <= CYCLE}
      end
    end
  end

  class Receiver
    @@peers = []

    class << self
      def read(&block)
        buf = ""
        @@pcap.each_data do |a|
          sender = a[0x1c,4].unpack("C4").join(".")
          next if sender == @@src[:ip_addr]
          
          case a[59]
            when "\1"
              buf << a[42,17]
            when "\0"
              str = (buf + a[42,18]).encode("ASCII-8BIT").unpack("A*").first
              begin
                name, func, body = MessagePack.unpack(str)
                case func
                  when MESSAGE
                    Peers.update(sender)
                    block.call(name, body)
                  when HEARTBEAT
                    Peers.update(sender)
                    puts "#{sender} exists."
                end
              rescue => e
              end
              buf = ""
          end
        end
      end
      
      def heartbeat
        Thread.new do
          loop do
            Sender.send(HEARTBEAT, 'heartbeat')
            sleep CYCLE
            Peers.leave
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
        @body = [@@name, func, body].to_msgpack
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

      def write(body)
        @arp = self.arp_header
        @arp.body = body
        @ip = self.ip_header
        @ip.body = @arp.to_s
        @@pcap.inject(@ip.to_s)
      end
    end
  end
end
