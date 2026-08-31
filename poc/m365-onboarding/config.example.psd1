@{
    SchemaVersion    = 1
    ExpectedTenantId = '151cd01a-1e81-40a9-b898-d8646e1a8760'
    VerifiedDomain   = 'vivolution.ae'

    Gateways = @(
        'sbc1.vivolution.ae'
        'sbc2.vivolution.ae'
    )
    SipSignalingPort = 5061

    PstnUsage         = 'Vivolution-POC-UAE'
    VoiceRoute        = 'Vivolution-POC-UAE-Plus971'
    VoiceRoutingPolicy = 'Vivolution-POC-UAE'
    NumberPattern     = '^(?:\+971000000200[12]|\+971[1-9][0-9]{7,8})$'

    # Replace all four values. The scripts reject placeholders, duplicate
    # identities/numbers, non-vivolution.ae UPNs, and non-UAE numbers.
    Users = @(
        @{
            Upn             = 'REPLACE_USER1@vivolution.ae'
            TelephoneNumber = '+971000000001'
        }
        @{
            Upn             = 'REPLACE_USER2@vivolution.ae'
            TelephoneNumber = '+971000000002'
        }
    )
}
