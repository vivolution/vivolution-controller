@{
    SchemaVersion    = 1
    ExpectedTenantId = '151cd01a-1e81-40a9-b898-d8646e1a8760'
    VerifiedDomain   = 'voice.vivolution.ae'

    Gateways = @(
        'sbc1.voice.vivolution.ae'
        'sbc2.voice.vivolution.ae'
    )
    SipSignalingPort = 5061

    PstnUsage         = 'Vivolution-POC-UAE'
    VoiceRoute        = 'Vivolution-POC-UAE-Plus971'
    VoiceRoutingPolicy = 'Vivolution-POC-UAE'
    NumberPattern     = '^\+971[1-9][0-9]{7,8}$'

    # Replace all four values. The scripts reject placeholders, duplicate
    # identities/numbers, non-voice.vivolution.ae UPNs, and non-UAE numbers.
    Users = @(
        @{
            Upn             = 'REPLACE_USER1@voice.vivolution.ae'
            TelephoneNumber = '+971000000001'
        }
        @{
            Upn             = 'REPLACE_USER2@voice.vivolution.ae'
            TelephoneNumber = '+971000000002'
        }
    )
}
