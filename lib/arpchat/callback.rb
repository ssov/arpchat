module ArpChat
  class Callback
    attr_accessor :receiveMessage, :leavePeer, :joinPeer
    def initialize
      @receiveMessage = Proc.new {|peer, body| "#{peer.name}(#{peer.src}) #{body}" }
      @leavePeer = Proc.new {|peer| "#{peer.ip} has left." }
      @joinPeer = Proc.new {|peer| "#{peer.ip} has joined." }
    end
  end
end
