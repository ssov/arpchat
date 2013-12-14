module ArpChat
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
end
