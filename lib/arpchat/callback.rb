module ArpChat
  class Callback
    attr_accessor :receiveMessage, :leftPeer, :joinPeer
    def initialize
      @receiveMessage = Proc.new {|src, name, body| "#{name}(#{src}) #{body}" }
      @leftPeer = Proc.new {|peer| "#{peer.ip} has left." }
      @joinPeer = Proc.new {|src| "#{src} has joined." }
    end
  end
end
