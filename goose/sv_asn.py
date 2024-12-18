# Auto-generated by asn1ate v.0.6.0 from sv.asn


from pyasn1.type import char, constraint, namedtype, tag, univ


class Data(univ.OctetString):
    pass


class OctStrSize8(univ.OctetString):
    pass


OctStrSize8.subtypeSpec = constraint.ValueSizeConstraint(8, 8)


class UtcTime(univ.OctetString):
    pass


class ASDU(univ.Sequence):
    pass


ASDU.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "svID",
        char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
    ),
    namedtype.OptionalNamedType(
        "datSet",
        char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)),
    ),
    namedtype.NamedType(
        "smpCnt",
        univ.Integer()
        .subtype(subtypeSpec=constraint.ValueRangeConstraint(0, 65535))
        .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)),
    ),
    namedtype.NamedType(
        "confRev",
        univ.Integer()
        .subtype(subtypeSpec=constraint.ValueRangeConstraint(0, 4294967295))
        .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)),
    ),
    namedtype.OptionalNamedType(
        "refrTm",
        UtcTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)),
    ),
    namedtype.NamedType(
        "smpSynch",
        univ.Integer()
        .subtype(subtypeSpec=constraint.ValueRangeConstraint(0, 255))
        .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)),
    ),
    namedtype.OptionalNamedType(
        "smpRate",
        univ.Integer()
        .subtype(subtypeSpec=constraint.ValueRangeConstraint(0, 65535))
        .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)),
    ),
    namedtype.NamedType("sample", Data().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
    namedtype.OptionalNamedType(
        "smpMod",
        univ.Integer()
        .subtype(subtypeSpec=constraint.ValueRangeConstraint(0, 65535))
        .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8)),
    ),
    namedtype.OptionalNamedType(
        "gmIdentity",
        OctStrSize8().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9)),
    ),
)


class OctStrSize1(univ.OctetString):
    pass


OctStrSize1.subtypeSpec = constraint.ValueSizeConstraint(1, 1)


class OctStrSize2(univ.OctetString):
    pass


OctStrSize2.subtypeSpec = constraint.ValueSizeConstraint(2, 2)


class OctStrSize4(univ.OctetString):
    pass


OctStrSize4.subtypeSpec = constraint.ValueSizeConstraint(4, 4)


class SavPdu(univ.Sequence):
    pass


SavPdu.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "noASDU",
        univ.Integer()
        .subtype(subtypeSpec=constraint.ValueRangeConstraint(1, 65535))
        .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
    ),
    namedtype.OptionalNamedType(
        "security",
        univ.Any().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)),
    ),
    namedtype.NamedType(
        "asdu",
        univ.SequenceOf(componentType=ASDU()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)),
    ),
)


class SampledValues(univ.Choice):
    pass


SampledValues.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "savPdu",
        SavPdu().subtype(implicitTag=tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0)),
    )
)
