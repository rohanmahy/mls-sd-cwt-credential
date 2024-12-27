---
title: "Messaging Layer Security credentials using Selective Disclosure CBOR Web Tokens"
abbrev: "MLS SD-CWT credentials"
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
 - Selective Disclosure
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

TODO Abstract


--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# MLS Credential

~~~
struct {
    opaque blinded_claim_hash<V>;
    opaque aead_encrypted_disclosure<V>;
} EncryptedDisclosure;

struct {
    CredentialType credential_type;
    select (Credential.credential_type) {
        case basic:
            opaque identity<V>;
        case x509:
            Certificate certificates<V>;
        case sd_cwt:
            opaque sd_kbt<V>;
            EncryptedDisclosure other_encrypted_disclosures<V>;
    };
} Credential;
~~~

An MLS SD-CWT Credential contains a Selective Disclosure Key Binding Token
(SD-KBT).


The credential can also include zero or more additional (encrypted) disclosures that are not disclosed in the SD-KBT.
Each disclosure is separately AEAD encrypted with a per-disclosure unique ephemeral key.
The per-disclosure encryption key allows the client to disclose an element to a specific subset of members, or (in the common case when the DS is privy to the ratchet tree) only to members of the group.
A specific way to safely encrypt and decrypt disclosures only for members of the group is described in {{member-only-disclosures}}.

## Specific header fields and claims in an SD-KBT and SD-CWT





The audience in the SD-KBT is either a representation of the MLS group, or a higher-level application structure associated with an MLS group or tightly-coupled collection of groups (for example, a chat room which maintains one MLS group for the main discussion and another for moderators to discuss the moderation of the room) such that being in one group without the collection would be nonsensical.


The subject in the SD-CWT represents a specific MLS client (for example a COSE key thumbprint, or a client ID URI). It should not use an identifier which represents multiple signature key pairs of the same type, or represents the same "user" on multiple devices.

# Member-only disclosures

This document defines two new MLS application components to facilitate sharing with members, its disclosures that are hidden from the DS.
It also defines a new MLS key schedule Exporter Label, `member_identity_disclosure_secret`.

These two application components provide a way to efficiently update encryption of disclosures, only when needed to achieve privacy from former members colluding with the DS.

~~~ aasvg
Leaf Node
  SD-CWT Credential
    SD-KBT
      Disclosures
      Issuer-signed CWT
    Other disclosures
     (individually AEAD encrypted) <------------------------------+
                          ^                                       |
                          |                                       |
    leaf_index, blinded_claim_hash,                               |
        encrypted_during_epoch                                    |
        (individual disclosure key encrypted w/ per-epoch key)    |
                          ^                                       |
                          |        OldEpochMemberEncryptionKeys:  |
                          |         (epoch, old_member_secret encrypted
                          |          with current
                          |          member_identity_disclosure_secret)
                          |                    ^
                          |                    |
MLS Key schedule, member_identity_disclosure_secret
~~~

During any epoch when a disclosure is added or updated, the ephemeral keys are encrypted using the `member_identity_disclosure_secret` for the epoch about to be committed.
Also the `member_identity_disclosure_secret`s for any previous epochs that are still being used to encrypt individual credentials are encrypted using the target epoch `member_identity_disclosure_secret` in the OldEpochMemberEncryptionKeys struct.

~~~
struct {
    opaque bytes<V>;
} BlindedClaimHash;

struct {
    uint32 leaf_index;
    BlindedClaimHash blinded_claim_hash;
    uint64 encrypted_during_epoch;
} PerDisclosureEpochEncryptor;

struct {
    PerDisclosureEpochEncryptor per_disclosure_epoch_map<V>;
} PerDisclosureEncryptionMap;

PerDisclosureEncryptionMap per_disclosure_encryption_map;

struct {
    BlindedClaimHash removed_disclosures<V>;
    PerDisclosureEpochEncryptor updated_disclosures<V>;
} PerDisclosureEncryptionMapUpdate;

PerDisclosureEncryptionMapUpdate per_disclosure_encryption_map_update;

struct {
    uint64 epoch;
    opaque encrypted_member_secret<V>;
} OldEpochEncryptionKey;

struct {
    OldEpochEncryptionKey old_epoch_encyption_keys<V>;
} OldEpochMemberEncryptionKeys;

OldEpochMemberEncryptionKeys old_epoch_member_encryption;
OldEpochMemberEncryptionKeys old_epoch_member_encryption_update;
~~~

## Post-Leaver Privacy (PLP)

Using the scheme above, any member-only disclosures are encrypted with a member-only key from the epoch in which these disclosures originally appear.
New joiners are provided a way to view the old per-epoch keys, so the new joiners can decrypt the member-only disclosures of pre-existing members, but that not every disclosure needs to be updated during every commit.

In many implementations, the AS and DS are tightly-coupled, so hiding information from the DS which is known to the SD-CWT Issuer is not a priority.
However, if PLP is desired, PLP updates are needed only when there is a Remove proposal (or SelfRemove proposal) and an Add proposal in the same or later commit.
In other words if Alice removes Bob in epoch 4, but the next add isn't until Alice adds Cathy in epoch 6, then a PLP update needs to be included in epoch 6.
This prevents Cathy from colluding with the DS to decrypt a disclosure about Bob.

To perform a PLP update, the (PerDisclosureEpochEncryptor) ephemeral keys encrypted from any epoch or earlier than the epoch containing a Remove or SelfRemove, are re-encrypted using the about-to-be committed `member_identity_disclosure_secret`. As with any other commit, unused previous epochs are pruned from OldEpochMemberEncryptionKeys, and all the remaining `member_identity_disclosure_secret`s for old epochs are encrypted using the target epoch `member_identity_disclosure_secret`.

# Generic form of EncryptWithLabel/DecryptWithLabel

For later

~~~
encrypted_disclosure = EncryptWithLabel(public_key, label, context, plaintext)

disclosure = DecryptWithLabel(private_key, label, context, kem_output, ciphertext)
~~~

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
