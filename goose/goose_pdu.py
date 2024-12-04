# Auto-generated by asn1ate v.0.6.0 from goose.asn

# (last modified on 2023-02-25 12:10:57.740412)


from pyasn1.type import char, constraint, namedtype, namedval, tag, univ, useful


class FloatingPoint(univ.OctetString):
    pass


class UtcTime(univ.OctetString):
    pass


class TimeOfDay(univ.OctetString):
    pass


class MMSString(char.UTF8String):
    pass


class Data10(univ.Choice):
    pass


Data10.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "array",
        univ.SequenceOf(componentType=univ.Any()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        ),
    ),
    namedtype.NamedType(
        "structure",
        univ.SequenceOf(componentType=univ.Any()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        ),
    ),
    namedtype.NamedType(
        "boolean",
        univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)),
    ),
    namedtype.NamedType(
        "bit-string",
        univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)),
    ),
    namedtype.NamedType(
        "integer",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)),
    ),
    namedtype.NamedType(
        "unsigned",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)),
    ),
    namedtype.NamedType(
        "floating-point",
        FloatingPoint().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)),
    ),
    namedtype.NamedType(
        "octet-string",
        univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9)),
    ),
    namedtype.NamedType(
        "visible-string",
        char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10)),
    ),
    namedtype.NamedType(
        "binary-time",
        TimeOfDay().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 12)),
    ),
    namedtype.NamedType(
        "bcd",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 13)),
    ),
    namedtype.NamedType(
        "booleanArray",
        univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 14)),
    ),
    namedtype.NamedType(
        "objId",
        univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 15)),
    ),
    namedtype.NamedType(
        "mMSString",
        MMSString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 16)),
    ),
    namedtype.NamedType(
        "utc-time",
        UtcTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 17)),
    ),
)

"""
class Data09(univ.Choice):
    pass


Data09.componentType = namedtype.NamedTypes(
    namedtype.NamedType('array', univ.SequenceOf(componentType=Data10()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.NamedType('structure', univ.SequenceOf(componentType=Data10()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    namedtype.NamedType('boolean', univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.NamedType('bit-string', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
    namedtype.NamedType('integer', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
    namedtype.NamedType('unsigned', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
    namedtype.NamedType('floating-point', FloatingPoint().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
    namedtype.NamedType('octet-string', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9))),
    namedtype.NamedType('visible-string', char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))),
    namedtype.NamedType('binary-time', TimeOfDay().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 12))),
    namedtype.NamedType('bcd', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 13))),
    namedtype.NamedType('booleanArray', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 14))),
    namedtype.NamedType('objId', univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 15))),
    namedtype.NamedType('mMSString', MMSString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 16))),
    namedtype.NamedType('utc-time', UtcTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 17)))
)


class Data08(univ.Choice):
    pass


Data08.componentType = namedtype.NamedTypes(
    namedtype.NamedType('array', univ.SequenceOf(componentType=Data09()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.NamedType('structure', univ.SequenceOf(componentType=Data09()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    namedtype.NamedType('boolean', univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.NamedType('bit-string', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
    namedtype.NamedType('integer', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
    namedtype.NamedType('unsigned', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
    namedtype.NamedType('floating-point', FloatingPoint().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
    namedtype.NamedType('octet-string', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9))),
    namedtype.NamedType('visible-string', char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))),
    namedtype.NamedType('binary-time', TimeOfDay().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 12))),
    namedtype.NamedType('bcd', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 13))),
    namedtype.NamedType('booleanArray', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 14))),
    namedtype.NamedType('objId', univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 15))),
    namedtype.NamedType('mMSString', MMSString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 16))),
    namedtype.NamedType('utc-time', UtcTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 17)))
)


class Data07(univ.Choice):
    pass


Data07.componentType = namedtype.NamedTypes(
    namedtype.NamedType('array', univ.SequenceOf(componentType=Data08()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.NamedType('structure', univ.SequenceOf(componentType=Data08()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    namedtype.NamedType('boolean', univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.NamedType('bit-string', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
    namedtype.NamedType('integer', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
    namedtype.NamedType('unsigned', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
    namedtype.NamedType('floating-point', FloatingPoint().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
    namedtype.NamedType('octet-string', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9))),
    namedtype.NamedType('visible-string', char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))),
    namedtype.NamedType('binary-time', TimeOfDay().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 12))),
    namedtype.NamedType('bcd', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 13))),
    namedtype.NamedType('booleanArray', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 14))),
    namedtype.NamedType('objId', univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 15))),
    namedtype.NamedType('mMSString', MMSString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 16))),
    namedtype.NamedType('utc-time', UtcTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 17)))
)


class Data06(univ.Choice):
    pass


Data06.componentType = namedtype.NamedTypes(
    namedtype.NamedType('array', univ.SequenceOf(componentType=Data07()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.NamedType('structure', univ.SequenceOf(componentType=Data07()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    namedtype.NamedType('boolean', univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.NamedType('bit-string', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
    namedtype.NamedType('integer', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
    namedtype.NamedType('unsigned', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
    namedtype.NamedType('floating-point', FloatingPoint().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
    namedtype.NamedType('octet-string', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9))),
    namedtype.NamedType('visible-string', char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))),
    namedtype.NamedType('binary-time', TimeOfDay().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 12))),
    namedtype.NamedType('bcd', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 13))),
    namedtype.NamedType('booleanArray', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 14))),
    namedtype.NamedType('objId', univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 15))),
    namedtype.NamedType('mMSString', MMSString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 16))),
    namedtype.NamedType('utc-time', UtcTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 17)))
)


class Data05(univ.Choice):
    pass


Data05.componentType = namedtype.NamedTypes(
    namedtype.NamedType('array', univ.SequenceOf(componentType=Data06()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.NamedType('structure', univ.SequenceOf(componentType=Data06()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    namedtype.NamedType('boolean', univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.NamedType('bit-string', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
    namedtype.NamedType('integer', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
    namedtype.NamedType('unsigned', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
    namedtype.NamedType('floating-point', FloatingPoint().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
    namedtype.NamedType('octet-string', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9))),
    namedtype.NamedType('visible-string', char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))),
    namedtype.NamedType('binary-time', TimeOfDay().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 12))),
    namedtype.NamedType('bcd', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 13))),
    namedtype.NamedType('booleanArray', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 14))),
    namedtype.NamedType('objId', univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 15))),
    namedtype.NamedType('mMSString', MMSString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 16))),
    namedtype.NamedType('utc-time', UtcTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 17)))
)


class Data04(univ.Choice):
    pass


Data04.componentType = namedtype.NamedTypes(
    namedtype.NamedType('array', univ.SequenceOf(componentType=Data05()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.NamedType('structure', univ.SequenceOf(componentType=Data05()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    namedtype.NamedType('boolean', univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.NamedType('bit-string', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
    namedtype.NamedType('integer', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
    namedtype.NamedType('unsigned', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
    namedtype.NamedType('floating-point', FloatingPoint().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
    namedtype.NamedType('octet-string', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9))),
    namedtype.NamedType('visible-string', char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))),
    namedtype.NamedType('binary-time', TimeOfDay().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 12))),
    namedtype.NamedType('bcd', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 13))),
    namedtype.NamedType('booleanArray', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 14))),
    namedtype.NamedType('objId', univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 15))),
    namedtype.NamedType('mMSString', MMSString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 16))),
    namedtype.NamedType('utc-time', UtcTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 17)))
)

"""


class Data03(univ.Choice):
    pass


Data03.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "array",
        univ.SequenceOf(componentType=Data10()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        ),
    ),
    namedtype.NamedType(
        "structure",
        univ.SequenceOf(componentType=Data10()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        ),
    ),
    namedtype.NamedType(
        "boolean",
        univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)),
    ),
    namedtype.NamedType(
        "bit-string",
        univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)),
    ),
    namedtype.NamedType(
        "integer",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)),
    ),
    namedtype.NamedType(
        "unsigned",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)),
    ),
    namedtype.NamedType(
        "floating-point",
        FloatingPoint().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)),
    ),
    namedtype.NamedType(
        "octet-string",
        univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9)),
    ),
    namedtype.NamedType(
        "visible-string",
        char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10)),
    ),
    namedtype.NamedType(
        "binary-time",
        TimeOfDay().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 12)),
    ),
    namedtype.NamedType(
        "bcd",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 13)),
    ),
    namedtype.NamedType(
        "booleanArray",
        univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 14)),
    ),
    namedtype.NamedType(
        "objId",
        univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 15)),
    ),
    namedtype.NamedType(
        "mMSString",
        MMSString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 16)),
    ),
    namedtype.NamedType(
        "utc-time",
        UtcTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 17)),
    ),
)


class Data02(univ.Choice):
    pass


Data02.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "array",
        univ.SequenceOf(componentType=Data03()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        ),
    ),
    namedtype.NamedType(
        "structure",
        univ.SequenceOf(componentType=Data03()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        ),
    ),
    namedtype.NamedType(
        "boolean",
        univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)),
    ),
    namedtype.NamedType(
        "bit-string",
        univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)),
    ),
    namedtype.NamedType(
        "integer",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)),
    ),
    namedtype.NamedType(
        "unsigned",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)),
    ),
    namedtype.NamedType(
        "floating-point",
        FloatingPoint().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)),
    ),
    namedtype.NamedType(
        "octet-string",
        univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9)),
    ),
    namedtype.NamedType(
        "visible-string",
        char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10)),
    ),
    namedtype.NamedType(
        "binary-time",
        TimeOfDay().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 12)),
    ),
    namedtype.NamedType(
        "bcd",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 13)),
    ),
    namedtype.NamedType(
        "booleanArray",
        univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 14)),
    ),
    namedtype.NamedType(
        "objId",
        univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 15)),
    ),
    namedtype.NamedType(
        "mMSString",
        MMSString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 16)),
    ),
    namedtype.NamedType(
        "utc-time",
        UtcTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 17)),
    ),
)


class Data01(univ.Choice):
    pass


Data01.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "array",
        univ.SequenceOf(componentType=Data02()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        ),
    ),
    namedtype.NamedType(
        "structure",
        univ.SequenceOf(componentType=Data02()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        ),
    ),
    namedtype.NamedType(
        "boolean",
        univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)),
    ),
    namedtype.NamedType(
        "bit-string",
        univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)),
    ),
    namedtype.NamedType(
        "integer",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)),
    ),
    namedtype.NamedType(
        "unsigned",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)),
    ),
    namedtype.NamedType(
        "floating-point",
        FloatingPoint().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)),
    ),
    namedtype.NamedType(
        "octet-string",
        univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9)),
    ),
    namedtype.NamedType(
        "visible-string",
        char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10)),
    ),
    namedtype.NamedType(
        "binary-time",
        TimeOfDay().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 12)),
    ),
    namedtype.NamedType(
        "bcd",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 13)),
    ),
    namedtype.NamedType(
        "booleanArray",
        univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 14)),
    ),
    namedtype.NamedType(
        "objId",
        univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 15)),
    ),
    namedtype.NamedType(
        "mMSString",
        MMSString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 16)),
    ),
    namedtype.NamedType(
        "utc-time",
        UtcTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 17)),
    ),
)


class Data(univ.Choice):
    pass


Data.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "array",
        univ.SequenceOf(componentType=Data01()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        ),
    ),
    namedtype.NamedType(
        "structure",
        univ.SequenceOf(componentType=Data01()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        ),
    ),
    namedtype.NamedType(
        "boolean",
        univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)),
    ),
    namedtype.NamedType(
        "bit-string",
        univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)),
    ),
    namedtype.NamedType(
        "integer",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)),
    ),
    namedtype.NamedType(
        "unsigned",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)),
    ),
    namedtype.NamedType(
        "floating-point",
        FloatingPoint().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)),
    ),
    namedtype.NamedType(
        "octet-string",
        univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9)),
    ),
    namedtype.NamedType(
        "visible-string",
        char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10)),
    ),
    namedtype.NamedType(
        "binary-time",
        TimeOfDay().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 12)),
    ),
    namedtype.NamedType(
        "bcd",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 13)),
    ),
    namedtype.NamedType(
        "booleanArray",
        univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 14)),
    ),
    namedtype.NamedType(
        "objId",
        univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 15)),
    ),
    namedtype.NamedType(
        "mMSString",
        MMSString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 16)),
    ),
    namedtype.NamedType(
        "utc-time",
        UtcTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 17)),
    ),
)


class ErrorReason(univ.Integer):
    pass


ErrorReason.namedValues = namedval.NamedValues(("other", 0), ("notFound", 1))


class IECGoosePdu(univ.Sequence):
    pass


IECGoosePdu.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "gocbRef",
        char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
    ),
    namedtype.NamedType(
        "timeAllowedtoLive",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)),
    ),
    namedtype.NamedType(
        "datSet",
        char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)),
    ),
    namedtype.OptionalNamedType(
        "goID",
        char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)),
    ),
    namedtype.NamedType("t", UtcTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
    namedtype.NamedType(
        "stNum",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)),
    ),
    namedtype.NamedType(
        "sqNum",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)),
    ),
    namedtype.DefaultedNamedType(
        "test",
        univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)).subtype(value=0),
    ),
    namedtype.NamedType(
        "confRev",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8)),
    ),
    namedtype.DefaultedNamedType(
        "ndsCom",
        univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9)).subtype(value=0),
    ),
    namedtype.NamedType(
        "numDatSetEntries",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10)),
    ),
    namedtype.NamedType(
        "allData",
        univ.SequenceOf(componentType=Data()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11)
        ),
    ),
)


class GetReferenceRequestPdu(univ.Sequence):
    pass


GetReferenceRequestPdu.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "ident",
        char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
    ),
    namedtype.NamedType(
        "offset",
        univ.SequenceOf(componentType=univ.Integer()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        ),
    ),
)


class GetElementRequestPdu(univ.Sequence):
    pass


GetElementRequestPdu.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "ident",
        char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
    ),
    namedtype.NamedType(
        "references",
        univ.SequenceOf(componentType=char.VisibleString()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        ),
    ),
)


class GSEMngtRequests(univ.Choice):
    pass


GSEMngtRequests.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "getGoReference",
        GetReferenceRequestPdu().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)),
    ),
    namedtype.NamedType(
        "getGOOSEElementNumber",
        GetElementRequestPdu().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)),
    ),
    namedtype.NamedType(
        "getGsReference",
        GetReferenceRequestPdu().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)),
    ),
    namedtype.NamedType(
        "getGSSEDataOffset",
        GetElementRequestPdu().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)),
    ),
)


class RequestResults(univ.Choice):
    pass


RequestResults.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "offset",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
    ),
    namedtype.NamedType(
        "reference",
        char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)),
    ),
    namedtype.NamedType(
        "error",
        ErrorReason().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)),
    ),
)


class GlbErrors(univ.Integer):
    pass


GlbErrors.namedValues = namedval.NamedValues(
    ("other", 0),
    ("unknownControlBlock", 1),
    ("responseTooLarge", 2),
    ("controlBlockConfigurationError", 3),
)


class PositiveNegative(univ.Choice):
    pass


PositiveNegative.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "responsePositive",
        univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.OptionalNamedType(
                    "datSet",
                    char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
                ),
                namedtype.NamedType(
                    "result",
                    univ.SequenceOf(componentType=RequestResults()).subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
                    ),
                ),
            )
        ).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)),
    ),
    namedtype.NamedType(
        "responseNegative",
        GlbErrors().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)),
    ),
)


class GSEMngtResponsePdu(univ.Sequence):
    pass


GSEMngtResponsePdu.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "ident",
        char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
    ),
    namedtype.OptionalNamedType(
        "confRev",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)),
    ),
    namedtype.NamedType("posNeg", PositiveNegative()),
)


class GSEMngtResponses(univ.Choice):
    pass


GSEMngtResponses.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "gseMngtNotSupported",
        univ.Null().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
    ),
    namedtype.NamedType(
        "getGoReference",
        GSEMngtResponsePdu().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)),
    ),
    namedtype.NamedType(
        "getGOOSEElementNumber",
        GSEMngtResponsePdu().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)),
    ),
    namedtype.NamedType(
        "getGsReference",
        GSEMngtResponsePdu().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)),
    ),
    namedtype.NamedType(
        "getGSSEDataOffset",
        GSEMngtResponsePdu().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)),
    ),
)


class RequestResponse(univ.Choice):
    pass


RequestResponse.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "requests",
        GSEMngtRequests().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)),
    ),
    namedtype.NamedType(
        "responses",
        GSEMngtResponses().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)),
    ),
)


class GSEMngtPdu(univ.Sequence):
    pass


GSEMngtPdu.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "stateID",
        univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
    ),
    namedtype.NamedType("requestResp", RequestResponse()),
)


class GOOSEpdu(univ.Choice):
    pass


GOOSEpdu.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "gseMngtPdu",
        GSEMngtPdu().subtype(implicitTag=tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0)),
    ),
    namedtype.NamedType(
        "goosePdu",
        IECGoosePdu().subtype(implicitTag=tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1)),
    ),
)