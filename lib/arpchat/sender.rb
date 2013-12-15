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

      def leave
        self.send(LEAVE, 'leave')
      end

      def message(body)
        self.send(MESSAGE, body)
      end

      def send(func, body, *option)
        raise Error::BodyEmpty if body.empty?
        packets = self.split(func, body)
 
        if option.first.class == Hash
          option = option.first
          dst_mac = option[:mac] unless option[:mac].nil?
          dst_ip = option[:ip] unless option[:ip].nil?
        end

        if packets.size == 1
          self.write(packets.first, ONLY, dst_mac, dst_ip)
        else
          packets.each do |i|
            case i
              when packets.first
                self.write(i, START, dst_mac, dst_ip)
              when packets.last
                self.write(i, LAST, dst_mac, dst_ip)
              else
                self.write(i, FRAGMENT, dst_mac, dst_ip)
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
        unless buf.empty?
          arr << buf + "\0"*(18-buf.size)
        end
        arr
      end

      def write(body, opcode=0, dst_mac, dst_ip)
        arp = self.arp_header
        arp.opcode = opcode
        arp.body = body
        arp.target_mac_addr = dst_mac unless dst_mac.nil?
        arp.target_ip_addr = dst_ip unless dst_ip.nil?
        ip = self.ip_header
        ip.body = arp.to_s
        @@pcap.inject(ip.to_s)
      end
    end
  end
end
