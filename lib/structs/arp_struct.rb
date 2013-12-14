class ArpStruct < BitStruct
  unsigned    :hardware_type,   16, "Hardware type"
  unsigned    :protocol_type,   16, "Protocol type"
  unsigned    :hardware_size,   8,  "Hardware size"
  unsigned    :protocol_size,   8,  "Protocol size"
  unsigned    :opcode,          16, "Opcode"
  
  hex_octets  :sender_mac_addr, 48, "Sender MAC Address"
  octets      :sender_ip_addr,  32, "Sender IP Address"
  hex_octets  :target_mac_addr, 48, "Target MAC Address"
  octets      :target_ip_addr,  32, "Target IP Address"

  rest        :body,                "Body"

  initial_value.hardware_type = 0x01
  initial_value.protocol_type = 0x0800
  initial_value.hardware_size = 0x06
  initial_value.protocol_size = 0x04
end
