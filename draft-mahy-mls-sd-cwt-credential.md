---
title: "Messaging Layer Security Credentials using Selective Disclosure JSON and CBOR Web Tokens"
abbrev: "MLS SD-JWT and SD-CWT Credentials"
category: info

docname: draft-mahy-mls-sd-cwt-credential-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Messaging Layer Security"
keyword:
 - MLS credential
 - SD-CWT
 - SD-KBT
 - SD-JWT
 - key binding
 - selective disclosure
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "rohanmahy/mls-sd-cwt-credential"
  latest: "https://rohanmahy.github.io/mls-sd-cwt-credential/draft-mahy-mls-sd-cwt-credential.html"

author:
 -
    fullname: Rohan Mahy
    organization: Rohan Mahy Consulting Services
    email: rohan.ietf@gmail.com

normative:

informative:


--- abstract

The Messaging Layer Security (MLS) protocol contains Credentials used to authenticate an MLS client with a signature key pair.
Selective Disclosure CBOR Web Tokens (SD-CWT) and Selective Disclosure JSON Web Tokens (SD-JWT) define token formats where the holder can selectively reveal claims about itself with strong integrity protection and cryptographic binding to the holder's key.
This document defines MLS credentials for both these token types.

--- middle

# Introduction

This document defines new MLS {{!RFC9420}} credential types for SD-CWT {{!I-D.ietf-spice-sd-cwt}} and SD-JWT {{!I-D.ietf-oauth-selective-disclosure-jwt}} tokens respectively.
The SD-CWT Credential contains a Selective Disclosure Key Binding Token (SD-KBT).
The SD-JWT Credential contains SD-JWT with Key Binding (SD-JWT+KB), which could be represented in the traditional data format, or in a more compact binary encoding.

The "holder" of one of these tokens could be the MLS client including the token in its Credential in its LeafNode (in a group or in a KeyPackage) or in an ExternalSender structure.

> Note: It is not necessary for an AS to selectively disclose any claims.
In other words, an Identity Provider that normally generates JWT or CWT web tokens could generate the same claim set, as long as the confirmation key is included and verified by the issuer.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The term Credential is used as defined in {{Section 5.3 of !RFC9420}}.
The terms MLS Distribution Service (DS) and MLS Authentication Service (AS) are used as defined in {{!RFC9750}}.
The terms MLS client, MLS group, LeafNode, KeyPackage, PublicMessage, PrivateMessage, ratchet tree, and GroupInfo are likewise common MLS terms defined in {{!RFC9420}}.

# New MLS Credential types

This document extends the list of defined CredentialTypes in MLS to include `sd_cwt` and `sd_jwt` types. Additional syntax and semantics are defined in the following subsections.

~~~ tls
struct {
    CredentialType credential_type;
    select (Credential.credential_type) {
        case basic:
            opaque identity<V>;
        case x509:
            Certificate certificates<V>;
        ...
        case sd_cwt:
            opaque sd_kbt<V>;
        case sd_jwt:
            SdJwt sd_jwt;
    };
} Credential;
~~~

The MLS architecture {{!RFC9750}} describes the Authentication Services as having the following three services (i.e. requirements):

1. Issue credentials to clients that attest to bindings between identities and signature key pairs
2. Enable a client to verify that a credential presented by another client is valid with respect to a reference identifier
3. Enable a group member to verify that a credential represents the same client as another credential

The consequence of this is that the consumer of the SD-CWT or SD-JWT needs to be able to determine both the MLS client and the application identity referred to in a token in a Credential.

## MLS SD-CWT Credential

An MLS SD-CWT Credential contains a single SD-KBT, containing an SD-CWT in the KBT protected header.
The SD-CWT contains zero of more disclosures (in the `sd_claims` header field).

Any party that can view the credential can read the disclosed claims.
For example if LeafNodes are visible to the MLS DS, because MLS handshake messages are conveyed in PublicMessage, the disclosed claims would also be visible to the DS.

The SD-CWT inside the credential MAY include zero or more encrypted disclosures (in the `sd_encrypted_claims` header field).
Each encrypted disclosure is separately AEAD encrypted with a per-disclosure unique ephemeral key and salt.
The per-disclosure encryption key allows the holder/MLS client to disclose an element to a specific subset of members, or (in the common case when the DS is privy to the ratchet tree) only to members of the group.
A proof of concept to decrypt encrypted disclosures only for members of the group is described in {{?I-D.mahy-mls-member-secrets}}.

The audience in the SD-KBT is either a representation of the MLS group, or a higher-level application structure associated with an MLS group or tightly-coupled collection of groups (for example, a chat room which maintains one MLS group for the main discussion and another for moderators to discuss the moderation of the room) such that being in one group without the collection would be nonsensical.

The subject in the SD-CWT represents a specific MLS client (for example a COSE key thumbprint, or a client ID URI).
It should not use an identifier which represents multiple signature key pairs of the same type, or represents the same "user" on multiple devices.


## MLS SD-JWT Credential

The SD-JWT Credential can be represented in the classic SD-JWT+KB data format defined in {{Section 4 of !I-D.ietf-oauth-selective-disclosure-jwt}} (shown below), or in a more compact binary representation.
MLS SD-JWT Credentials MUST include the Key Binding.

> **TODO**: Discuss if the LeafNode signature over the Credential is sufficient

The classic format uses only characters from the unpadded base64url character set (Section 5 of {{!RFC4648}}) plus the period (`.`) character to separate the three parts of the `Issuer-signed JWT`, and the tilde (`~`) character to separate disclosures from the other components.

~~~
<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~<KB-JWT>
~~~
{: title="SD-JWT+KB in classic format"}

This document also defines a "compacted" format where each of the components of the `Issuer-signed JWT`, every Disclosure, and the `KB-JWT` are base64url decoded and stored in individual fields in the `SdJwt` struct.

~~~ tls
struct {
    Bool compacted;
    select (compacted) {
        case true:
            opaque protected<V>;
            opaque payload<V>;
            opaque signature<V>;
            SdJwtDisclosure disclosures<V>;
            opaque sd_jwt_key_binding<V>;
        case false:
            opaque sd_jwt_kb<V>;
    };
} SdJwt;

enum {
  false(0),
  true(1)
} Bool;
~~~

> The compacted variant allows implementations to tradeoff reduced size for the extra processing cost of base64url encoding and decoding the Credential.


# Security Considerations

The privacy considerations in SD-CWT, SD-JWT, and MLS apply.
TODO more security.


# Privacy Considerations

The privacy considerations in SD-CWT and SD-JWT apply. The privacy considerations of MLS are largely discussed in {{!RFC9750}}.
TODO more privacy.

# IANA Considerations

This document requests IANA to add the following entries to the MLS Credential Types registry. Please replace RFCXXXX with the RFC of this document.

## SD-CWT Credential

- Value: 0x0005 (suggested)
- Name: sd_cwt
- Recommended: Y
- Reference: RFCXXXX

## SD-JWT Credential

- Value: 0x0006 (suggested)
- Name: sd_jwt
- Recommended: Y
- Reference: RFCXXXX


--- back

# Acknowledgments
{:numbered="false"}

Thanks to Richard Barnes for his comment.
