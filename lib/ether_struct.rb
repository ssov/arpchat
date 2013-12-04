class EtherStruct < BitStruct
  hex_octets :dst_addr, 48, "Destination Address"
  hex_octets :src_addr, 48, "Source Address"
  unsigned   :type,     16, "Type"
  rest       :body,         "Body"
end
