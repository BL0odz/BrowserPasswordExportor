
class ASN1(object):
    
    SEQUENCE = 0x30
    OCTETSTRING = 4
    OBJECTIDENTIFIER = 6
    INTEGER = 2
    NULL = 5

    finished = False

    def __init__(self, item2:bytes) -> None:
        # ASN1 parse structure
        #self.RootSequence = SequenceStruct()
        #self.Sequence = dict()
        self.RootSequence = dict()
        self.RootSequence["Sequence"] = []
        self.RootSequence["Integer"] = []
        self.RootSequence["OctetString"] = []
        self.RootSequence["ObjectIdentifier"] = []

        self.Parse(item2)

    def CheckLengthForm(self, length:int):
        if (length & 0x80) > 0:
            return (length & 0x7f) + 1
        else:
            return 1

    def ParseTLV(self, SequenceCurrent:dict, index, asnBytesLength) -> int:
        i = index
        typ = self.Asn1ByteArray[i]
        i += 1
        lengthform = self.CheckLengthForm(self.Asn1ByteArray[i])
        length = self.Asn1ByteArray[i + lengthform - 1]
        
        i += lengthform
        
        if typ == self.SEQUENCE:
            #sqc = SequenceStruct()
            sqc = dict()
            sqc["Sequence"] = []
            sqc["Integer"] = []
            sqc["OctetString"] = []
            sqc["ObjectIdentifier"] = []
            SequenceCurrent["Sequence"].append(sqc)
            i +=  self.ParseTLV(sqc, i, i + length - 1)
        
        elif typ == self.OBJECTIDENTIFIER:
            SequenceCurrent["ObjectIdentifier"].append(self.Asn1ByteArray[i:i+length])
            i += length

        elif typ == self.OCTETSTRING:
            SequenceCurrent["OctetString"].append(self.Asn1ByteArray[i:i+length])
            i += length

        elif typ == self.INTEGER:
            SequenceCurrent["Integer"].append(self.Asn1ByteArray[i:i+length])
            i += length

        elif typ == self.NULL:
            if lengthform > 1:
                i += 1

        else:
            i += length

        while i < asnBytesLength:
            i += self.ParseTLV(SequenceCurrent, i, asnBytesLength)

        self.finished = True
        return i - index

    def Parse(self, item2:bytes) -> None:
        self.Asn1ByteArray = item2
        self.ParseTLV(self.RootSequence, 0, len(item2))
