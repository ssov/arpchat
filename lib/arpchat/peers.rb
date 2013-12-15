module ArpChat
  class Peers
    @@peers = []
    class Peer
      attr_accessor :ip, :mac, :updated_at, :name
      def initialize(*args)
        args = args.first
        args.each do |k, v|
          self.instance_variable_set("@#{k}".to_sym, v)
        end

        name? if @name.nil?
      end

      def update(*args)
        args = args.first
        args.each do |k, v|
          self.instance_variable_set("@#{k}".to_sym, v)
        end
      end

      def name?
        Sender.send(YOURNAME, 'name?', {mac:@mac, ip:@ip})
      end
    end

    class << self
      def update(args)
        args.update(:updated_at => Time.now)
        if @@peers.select{|peer| peer.ip == args[:ip]} == []
          peer = Peer.new(args)
          @@peers << peer
          peer
        else
          begin
            obj = @@peers.select{|peer| peer.ip == args[:ip]}.first
            obj.update(args)
          rescue
          end
        end
      end

      def leave(ip)
        peer = @@peers.select{|peer| peer.ip == ip}
        @@peers.delete_if{|peer| peer.ip == ip}
        @@proc.leavePeer.call(peer.first)
      end

      def exist?
        time = Time.now
        @@peers.select{|peer| (time - peer.updated_at) > CYCLE}.each do |peer|
          @@proc.leftPeer.call(peer)
        end 
        @@peers.select!{|peer| (time - peer.updated_at) <= CYCLE}
      end

      def search(src)
        @@peers.select{|peer| peer.ip == src}.first
      end
    end
  end
end
