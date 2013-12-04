require 'arpchat'

describe ArpChat do
  describe "init" do
    it "name is 'anonymous'" do
      expect(
        ArpChat.class_variable_get(:@@name)
      ).to eq 'anonymous'
    end

    it "pcap is Pcap class" do
      expect(
        ArpChat.class_variable_get(:@@pcap).class
      ).to eq PCAPRUB::Pcap
    end

    it {
      expect(
        ArpChat.class_variable_get(:@@src)[:mac_addr]
      ).to eq "10:6f:3f:34:21:5f"
    }

    it {
      expect(
        ArpChat.class_variable_get(:@@src)[:ip_addr]
      ).to eq "123.234.123.234"
    }

    it {
      expect(
        ArpChat.class_variable_get(:@@dst)[:mac_addr]
      ).to eq "ff:ff:ff:ff:ff:ff"
    }

    it {
      expect(
        ArpChat.class_variable_get(:@@dst)[:ip_addr]
      ).to eq "123.234.123.234"
    }
  end

  describe :name do
    it "should set name" do
      @name = "hogehoge-#{Time.now.to_f}"
      ArpChat.name(@name)
      expect(
        ArpChat.class_variable_get(:@@name)
      ).to eq @name
    end
  end

  describe :send do
    context "when body is empty" do
      it "raise ArpChat::BodyEmpty" do
        expect {
          ArpChat.send("")
        }.to raise_error(ArpChat::Error::BodyEmpty)
      end
    end
  end

  describe :ip_header do
    before do
      @ip = ArpChat.ip_header
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
      @arp = ArpChat.arp_header
    end

    it {
      expect(@arp.opcode).to eq 0x01
    }

    it {
      expect(@arp.sender_mac_addr).to eq "10:6f:3f:34:21:5f"
    }

    it {
      expect(@arp.sender_ip_addr).to eq "123.234.123.234"
    }

    it {
      expect(@arp.target_mac_addr).to eq "ff:ff:ff:ff:ff:ff"
    }

    it {
      expect(@arp.target_ip_addr).to eq "123.234.123.234"
    }
  end

  describe :write do
    it {
      expect(ArpChat.write("hogehoge")).not_to eq -1
    }
  end
end
