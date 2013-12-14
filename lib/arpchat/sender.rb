module ArpChat
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
