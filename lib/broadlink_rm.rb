require 'openssl'
require 'socket'


module BroadlinkRM
  class Device
    def self.discover
      self.discover_local
    end

    def self.discover_remote(host:, port: )
      discover_socket.send(discover_packet(local_ip, listen_port).pack("C*"), 0, host, port)
      response, addr = broadcast_socket.recvfrom(1024)
      response_packet = response.unpack("C*")
      host = addr[3]
      port = addr[1]
      mac = response_packet[0x3a...0x40]
      return new( host: host, mac: mac, port: port )
    end

    def self.discover_local
      local_ip = ::Socket.ip_address_list.find{|a| a.ipv4_private?}.ip_address.split(".").map(&:to_i)
      discover_socket.send(discover_packet(local_ip, listen_port).pack("C*"), 0, "255.255.255.255", 80)
      response, addr = discover_socket.recvfrom(1024)
      response_packet = response.unpack("C*")
      host = addr[3]
      port = addr[1]
      mac = response_packet[0x3a...0x40]
      return new( host: host, mac: mac, port: port )
    end

    def self.discover_socket
      @discover_socket ||= begin
        s = UDPSocket.new()
        s.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
        s.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, 1)
        s.bind('0.0.0.0', listen_port)
        s
      end
    end

    def self.discover_packet(respond_to_ip_address, respond_to_port)
      packet = Array.new(0x30, 0)

      if respond_to_ip_address.is_a?(String)
        respond_to_ip_address = respond_to_ip_address.split('.').map{ |octet| octet.to_i }
      end

      if respond_to_port.is_a?(String)
        respond_to_port = respond_to_port.to_i
      end

      time_zone = Time.now.utc_offset/-3600
      if time_zone < 0
        packet[0x08] = 0xff + time_zone - 1
        packet[0x09] = 0xff
        packet[0x0a] = 0xff
        packet[0x0b] = 0xff
      else
        packet[0x08] = time_zone
        packet[0x09] = 0
        packet[0x0a] = 0
        packet[0x0b] = 0
      end
      packet[0x0c] = Time.now.year & 0xff
      packet[0x0d] = Time.now.year >> 8
      packet[0x0e] = Time.now.min
      packet[0x0f] = Time.now.hour
      packet[0x10] = Time.now.year % 100
      packet[0x11] = Time.now.wday
      packet[0x12] = Time.now.day
      packet[0x13] = Time.now.month
      packet[0x18] = respond_to_ip_address[0]
      packet[0x19] = respond_to_ip_address[1]
      packet[0x1a] = respond_to_ip_address[2]
      packet[0x1b] = respond_to_ip_address[3]
      packet[0x1c] = respond_to_port & 0xff
      packet[0x1d] = respond_to_port >> 8
      packet[0x26] = 6
      checksum = 0xbeaf

      packet.each do |val|
        checksum += val
      end
      checksum = checksum & 0xffff
      packet[0x20] = checksum & 0xff
      packet[0x21] = checksum >> 8
      return packet
    end

    def self.listen_ip_address
      ENV['LISTEN_IP'] || "0.0.0.0"
    end

    def self.listen_port
      ENV['LISTEN_PORT'] || ENV['PORT'] || 8889
    end


    attr_accessor :host, :port, :count, :id, :mac, :key, :iv

    def initialize(host:, mac:, port:)
      @host = host
      @mac = mac
      @port = port
      @count = rand(0xffff)
      @id = [0, 0, 0, 0]
      @key = [0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02]
      @iv = [0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58]
    end

    def send_packet(command, payload)
      @count = (@count + 1) & 0xffff
      packet = Array.new(0x38, 0)
      packet[0x00] = 0x5a
      packet[0x01] = 0xa5
      packet[0x02] = 0xaa
      packet[0x03] = 0x55
      packet[0x04] = 0x5a
      packet[0x05] = 0xa5
      packet[0x06] = 0xaa
      packet[0x07] = 0x55
      packet[0x24] = 0x2a
      packet[0x25] = 0x27
      packet[0x26] = command
      packet[0x28] = @count & 0xff
      packet[0x29] = @count >> 8
      packet[0x2a] = @mac[5]
      packet[0x2b] = @mac[4]
      packet[0x2c] = @mac[3]
      packet[0x2d] = @mac[2]
      packet[0x2e] = @mac[1]
      packet[0x2f] = @mac[0]
      packet[0x30] = @id[0]
      packet[0x31] = @id[1]
      packet[0x32] = @id[2]
      packet[0x33] = @id[3]

      checksum = payload.inject(0xbeaf){|sum,x| sum + x.to_i } & 0xffff
      packet[0x34] = checksum & 0xff
      packet[0x35] = (checksum & 0xFF00) >> 8

      aes = OpenSSL::Cipher::AES128.new(:CBC)
      aes.padding = 0
      aes.encrypt
      aes.key = self.key.pack("C*")
      aes.iv = self.iv.pack("C*")
      payload = aes.update(payload.pack("C*")).unpack("C*")

      packet.concat(payload)

      checksum = (0xbeaf + packet.inject(0){|sum,x| (x + sum) }) & 0xffff
      packet[0x20] = checksum & 0xff
      packet[0x21] = (checksum & 0xff00) >> 8

      socket.send(packet.pack("C*"), 0)
      response, addr = socket.recvfrom(1024)
      return response
    end

    def send_data(data)
      packet = [0x02, 0x00, 0x00, 0x00]
      packet.concat data
      send_packet(0x6a, packet)
    end

    def auth
      payload = Array.new(0x50, 0)
      payload[0x04] = 0x31
      payload[0x05] = 0x31
      payload[0x06] = 0x31
      payload[0x07] = 0x31
      payload[0x08] = 0x31
      payload[0x09] = 0x31
      payload[0x0a] = 0x31
      payload[0x0b] = 0x31
      payload[0x0c] = 0x31
      payload[0x0d] = 0x31
      payload[0x0e] = 0x31
      payload[0x0f] = 0x31
      payload[0x10] = 0x31
      payload[0x11] = 0x31
      payload[0x12] = 0x31
      payload[0x1e] = 0x01
      payload[0x2d] = 0x01
      payload[0x30] = 'T'.unpack("C*")[0]
      payload[0x31] = 'e'.unpack("C*")[0]
      payload[0x32] = 's'.unpack("C*")[0]
      payload[0x33] = 't'.unpack("C*")[0]
      payload[0x34] = ' '.unpack("C*")[0]
      payload[0x35] = ' '.unpack("C*")[0]
      payload[0x36] = '1'.unpack("C*")[0]

      response = self.send_packet(0x65, payload)

      enc_payload = response[0x38..-1]

      aes = OpenSSL::Cipher::AES128.new(:CBC)
      aes.decrypt
      aes.padding = 0
      aes.iv = self.iv.pack("C*")
      aes.key = self.key.pack("C*")
      payload = aes.update(enc_payload) + aes.final
      self.id = payload[0x00...0x04].unpack("C*")
      self.key = payload[0x04...0x14].unpack("C*")
    end

    def enter_learning
      packet = Array.new(16,0)
      packet[0] = 3
      send_packet(0x6a, packet)
    end

    def check_data
      packet = Array.new(16,0)
      packet[0] = 4
      response = send_packet(0x6a, packet)
      err = response[0x22].ord | (response[0x23].ord << 8)
      if err == 0
        aes = OpenSSL::Cipher.new('AES-128-CBC')
        aes.decrypt
        aes.iv = self.iv.pack("C*")
        aes.key = self.key.pack("C*")
        aes.auth_data = ""
        payload = aes.update(response[0x38..-1])
        payload[0x04..-1].unpack("C*")
      end
    end

    def socket(host: @host, port: @port)
      @socket ||= begin
        s = UDPSocket.new()
        s.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
        s.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, 1)
        s.connect(host, port)
        s
      end
    end

    def to_hash
      { mac: mac, host: host, port: port }
    end

  end
end
