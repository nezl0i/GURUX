import abc
import crcmod  # pip3 install crcmod


class CRC_Variable(abc.ABC):

    @abc.abstractmethod
    def check(self, packet):
        pass

    @staticmethod
    def protocol(variable):
        PROTOCOL = {
            'dlms': Check_CRC(0x11021, 0x0000, True, 0xFFFF),
            'modbus': Check_CRC(0x18005, 0xFFFF, True, 0x0000)
        }

        return PROTOCOL[variable]


class Check_CRC(CRC_Variable):
    def __init__(self, poly, init, rev, xor):
        self.poly = poly
        self.init = init
        self.rev = rev
        self.xor = xor

    def check(self, packet: str | list) -> str:
        if isinstance(packet, str):
            packet = ''.join(packet.split(' '))
        elif isinstance(packet, list):
            packet = ''.join(map(lambda x: "{:02X}".format(x), packet))
        crc16 = crcmod.mkCrcFun(self.poly, self.init, self.rev, self.xor)
        fcs = crc16(bytes.fromhex(packet))
        _crc = "{0:02X}".format(fcs)
        CRC = f"{_crc[2:]} {_crc[:2]}"
        return CRC

# crc_modbus = CRC_Variable.protocol('modbus')
# crc_dlms = CRC_Variable.protocol('dlms')

# print(crc_modbus.check("A0 19 61"))
# print(crc_modbus.check([0xA0, 0x19, 0x61]))
# print(crc_dlms.check("A0 19 61"))
# print(crc_dlms.check([0xA0, 0x19, 0x61]))
