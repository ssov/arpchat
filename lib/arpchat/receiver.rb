module ArpChat
  class Receiver
    @@peers = []

    class << self
      def read
        buf = {}
        @@pcap.each_data do |a|
          src_ip = a[0x1c,4].unpack("C4").join(".")
          dst_ip = a[0x26,4].unpack("C4").join(".")
          src_mac = a[0x06,6].unpack("C*").map{|i| i.to_s(16)}.join(":")

          next if src_ip == @@src[:ip_addr]
          next unless dst_ip == CHATROOM_ADDR || dst_ip == @@src[:ip_addr]

          case a[0x15].unpack("U").first
            when ONLY
              buf[src_ip] = a[42,18].encode("ASCII-8BIT").unpack("A*").first
              self.switch(src_ip, src_mac, buf[src_ip])
            when START
              buf[src_ip] = a[42,18]
            when FRAGMENT
              buf[src_ip] += a[42,18]
            when LAST
              buf[src_ip] = (buf[src_ip] + a[42,18]).encode("ASCII-8BIT").unpack("A*").first
              self.switch(src_ip, src_mac, buf[src_ip])
          end
        end
      end
      
      def switch(src_ip, src_mac, str)
        begin
          name, func, body = MessagePack.unpack(str)
        rescue => e
          # unpack error
          return
        end

        case func
          when MESSAGE
            Peers.update(ip: src_ip, mac: src_mac)
            peer = Peers.search(src_ip)
            return if peer.nil?
            begin
              @@proc.receiveMessage.call(peer, body)
            rescue => e
              raise ProcError
            end
          when HEARTBEAT
            Peers.update(ip: src_ip, mac: src_mac)
          when JOIN
            peer = Peers.update(ip: src_ip, mac: src_mac, name: name)
            @@proc.joinPeer.call(peer)
          when LEAVE
            Peers.leave(src_ip)
          when YOURNAME
            Sender.send(MYNAME, @@name, {mac:src_mac, ip:src_ip})
          when MYNAME
            Peers.update(ip: src_ip, name: body)
        end
      end
    end
  end
end
