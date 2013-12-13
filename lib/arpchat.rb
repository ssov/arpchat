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
  JOIN = 0x20

  ONLY = 0x04
  START = 0x01
  FRAGMENT = 0x02
  LAST = 0x03

  @@pcap = Pcap.open_live("en0", 0xffff, false, 1)
  @@pcap.setfilter('arp')

  @@name = "anonymous"
  @@src = { :mac_addr => "10:6f:3f:34:21:5f",
            :ip_addr => "224.#{rand(255)}.#{rand(255)}.#{rand(255)}" }
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
        Peers.left
      end
    end
  end

  class Proc
    attr_accessor :receiveMessage, :leftPeer, :joinPeer
  end

  def configure(&block)
    @@proc = Proc.new
    block.call(@@proc)
  end

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

      def left
        time = Time.now
        @@peers.select{|peer| (time - peer.updated_at) > CYCLE}.each do |peer|
          @@proc.leftPeer.call(peer)
        end 
        @@peers.select!{|peer| (time - peer.updated_at) <= CYCLE}
      end
    end
  end

  class Receiver
    @@peers = []

    class << self
      def read
        buf = {}
        @@pcap.each_data do |a|
          src = a[0x1c,4].unpack("C4").join(".")
          dst = a[0x26,4].unpack("C4").join(".")
          next if src == @@src[:ip_addr]
          next unless dst == CHATROOM_ADDR

          case a[0x15].unpack("U").first
            when ONLY
              buf[src] = a[42,18].encode("ASCII-8BIT").unpack("A*").first
              self.switch(src, buf[src])
            when START
              buf[src] = a[42,18]
            when FRAGMENT
              buf[src] += a[42,18]
            when LAST
              buf[src] = (buf[src] + a[42,18]).encode("ASCII-8BIT").unpack("A*").first
              self.switch(src, buf[src])
          end
        end
      end
      
      def switch(src, str)
        begin
          name, func, body = MessagePack.unpack(str)
        rescue => e
          # unpack error
          return
        end

        case func
          when MESSAGE
            Peers.update(src)
            begin
              @@proc.receiveMessage.call(src, name, body)
            rescue => e
              raise ProcError
            end
          when HEARTBEAT
            Peers.update(src)
          when JOIN
            @@proc.joinPeer.call(src)
            Peers.update(src)
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

      def join
        self.send(JOIN, 'join')
      end

      def send(func, body)
        raise Error::BodyEmpty if body.empty?
        packets = self.split(func, body)
        if packets.size == 1
          self.write(packets.first, ONLY)
        else
          packets.each do |i|
            case i
              when packets.first
                self.write(i, START)
              when packets.last
                self.write(i, LAST)
              else
                self.write(i, FRAGMENT)
            end
          end
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
        )
      end

      def split(func, body)
        body = [@@name, func, body].to_msgpack
        arr = []
        buf = ""

        body.split(//).each do |i|
          buf << i
          if buf.size == 18
            arr << buf
            buf = ""
          end
        end
        arr << buf + "\0"*(18-buf.size)

        arr.map!{|a| a.encode("ASCII-8BIT")}
      end

      def write(body, opcode=0)
        arp = self.arp_header
        arp.opcode = opcode
        arp.body = body
        ip = self.ip_header
        ip.body = arp.to_s
        @@pcap.inject(ip.to_s)
      end
    end
  end
end
