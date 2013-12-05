require 'arpchat'

describe ArpChat::Sender do
  describe "init" do
    it "name is 'anonymous'" do
      expect(
        ArpChat::Sender.class_variable_get(:@@name)
      ).to eq 'anonymous'
    end

    it "pcap is Pcap class" do
      expect(
        ArpChat::Sender.class_variable_get(:@@pcap).class
      ).to eq PCAPRUB::Pcap
    end

    it {
      expect(
        ArpChat::Sender.class_variable_get(:@@src)[:mac_addr]
      ).to eq "10:6f:3f:34:21:5f"
    }

    it {
      expect(
        ArpChat::Sender.class_variable_get(:@@dst)[:mac_addr]
      ).to eq "ff:ff:ff:ff:ff:ff"
    }

    it {
      expect(
        ArpChat::Sender.class_variable_get(:@@dst)[:ip_addr]
      ).to eq "224.0.0.251"
    }
  end

  describe :name do
    it "should set name" do
      @name = "hogehoge-#{Time.now.to_f}"
      ArpChat::Sender.name(@name)
      expect(
        ArpChat::Sender.class_variable_get(:@@name)
      ).to eq @name
    end
  end

  describe :send do
    context "when body is empty" do
      it "raise ArpChat::Sender::BodyEmpty" do
        expect {
          ArpChat::Sender.send("")
        }.to raise_error(ArpChat::Sender::Error::BodyEmpty)
      end
    end
    ArpChat::Sender.send("あいうえおかきくけこさしすせそ")
  end

  describe :ip_header do
    before do
      @ip = ArpChat::Sender.ip_header
    end

    it {
      expect(@ip.type).to eq 0x0806
    }

    it {
      expect(@ip.dst_addr).to eq "ff:ff:ff:ff:ff:ff"
    }

    it {
      expect(@ip.src_addr).to eq "10:6f:3f:34:21:5f"
    }
  end

  describe :arp_header do
    before do
      @arp = ArpChat::Sender.arp_header
    end

    it {
      expect(@arp.opcode).to eq 0x01
    }

    it {
      expect(@arp.sender_mac_addr).to eq "10:6f:3f:34:21:5f"
    }

    it {
      expect(@arp.target_mac_addr).to eq "ff:ff:ff:ff:ff:ff"
    }

    it {
      expect(@arp.target_ip_addr).to eq "224.0.0.251"
    }
  end

  describe :split do
    it {
      @arr = ArpChat::Sender.split("あいうえおかきくけこさしすせそ")
      expect(@arr).to eq ["B0D0F0H0J0K0M0O0Q\u0001", "0S0U0W0Y0[0]0\u0000\u0000\u0000\u0000\u0000"]
    }
  end

  describe :write do
    it {
      expect(ArpChat::Sender.write("hogehoge")).not_to eq -1
    }
  end
end
