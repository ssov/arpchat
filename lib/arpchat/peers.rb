module ArpChat
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
end
