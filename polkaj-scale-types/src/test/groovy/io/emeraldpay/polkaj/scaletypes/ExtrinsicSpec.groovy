package io.emeraldpay.polkaj.scaletypes

import io.emeraldpay.polkaj.ss58.SS58Type
import io.emeraldpay.polkaj.types.Address
import nl.jqno.equalsverifier.EqualsVerifier
import nl.jqno.equalsverifier.Warning
import spock.lang.Specification

class ExtrinsicSpec extends Specification {

    def "Equals"() {
        when:
        def v = EqualsVerifier.forClass(Extrinsic)
                .withPrefabValues(SS58Type.Network,
                        SS58Type.Network.CANARY,
                        SS58Type.Network.LIVE)
                .withPrefabValues(Address,
                        Address.from("GksmaqmLPbfQhsNgT2S5GcwwTkGXCpkPU8FDzxP4siKPAVu"),
                        Address.from("ED3aw4s68wTDscCbWnCCw94qSrkA1D8HcUXC8ytaoM2X2xd"))
                .withPrefabValues(Extrinsic.TransactionInfo,
                        new Extrinsic.TransactionInfo().tap {
                            sender = Address.from("GksmaqmLPbfQhsNgT2S5GcwwTkGXCpkPU8FDzxP4siKPAVu")
                        },
                        new Extrinsic.TransactionInfo().tap {
                            sender = Address.from("ED3aw4s68wTDscCbWnCCw94qSrkA1D8HcUXC8ytaoM2X2xd")
                        }
                )
                .suppress(Warning.STRICT_INHERITANCE)
                .suppress(Warning.NONFINAL_FIELDS)
        then:
        v.verify()
    }

    def "TransactionInfo Equals"() {
        when:
        def v = EqualsVerifier.forClass(Extrinsic.TransactionInfo)
                .withPrefabValues(SS58Type.Network,
                        SS58Type.Network.CANARY,
                        SS58Type.Network.LIVE)
                .withPrefabValues(Address,
                        Address.from("GksmaqmLPbfQhsNgT2S5GcwwTkGXCpkPU8FDzxP4siKPAVu"),
                        Address.from("ED3aw4s68wTDscCbWnCCw94qSrkA1D8HcUXC8ytaoM2X2xd"))
                .suppress(Warning.STRICT_INHERITANCE)
                .suppress(Warning.NONFINAL_FIELDS)
                .suppress(Warning.STRICT_HASHCODE)
        then:
        v.verify()
    }

    def "SR25519 Signature Equals"() {
        when:
        def v = EqualsVerifier.forClass(Extrinsic.SR25519Signature)
                .usingGetClass()
        then:
        v.verify()
    }

    def "ED25519 Signature Equals"() {
        when:
        def v = EqualsVerifier.forClass(Extrinsic.ED25519Signature)
                .usingGetClass()
        then:
        v.verify()
    }
}
