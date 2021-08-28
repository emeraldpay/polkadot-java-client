package io.emeraldpay.polkaj.tx

import io.emeraldpay.polkaj.scaletypes.BalanceTransfer
import io.emeraldpay.polkaj.scaletypes.BalanceTransferWriter
import io.emeraldpay.polkaj.scaletypes.Extrinsic
import io.emeraldpay.polkaj.types.Address
import io.emeraldpay.polkaj.types.DotAmount
import io.emeraldpay.polkaj.types.Hash256
import io.emeraldpay.polkaj.types.Hash512
import org.apache.commons.codec.binary.Hex
import spock.lang.Specification

class ExtrinsicSignerSpec extends Specification {

    def "Sign standard"() {
        // PAYLOAD STRUCTURE:
        // a4 <- encoded call size (omitted for signature)
        // 0500 <- method
        // 8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48 <- to
        // 0b <- amount size
        // 0b0030ef7dba02 <- amount
        // 00 <- era
        // 1c <- nonce
        // 00 <- tip
        // 12000000 <- runtime version
        // 03000000 <- tx version
        // 4c0bdd177c17ca145ad9a3e76d092d4d4baa8add4fa8c78cc2fbbf8e3cbd5122 <- genesis
        // 4c0bdd177c17ca145ad9a3e76d092d4d4baa8add4fa8c78cc2fbbf8e3cbd5122 <- block

        setup:
        ExtrinsicContext extrinsic = ExtrinsicContext.newBuilder()
                .runtime(3, 0x12)
                .genesis(Hash256.from("0x4c0bdd177c17ca145ad9a3e76d092d4d4baa8add4fa8c78cc2fbbf8e3cbd5122"))
                .nonce(7)
                .build()
        BalanceTransfer call = new BalanceTransfer(5, 0).tap {
            destination = TestKeys.bob
            balance = DotAmount.fromDots(300) // 02 ba 7d ef 30 00 -> 0030ef7dba02
        }
        ExtrinsicSigner signer = new ExtrinsicSigner<>(new BalanceTransferWriter())
        when:
        def payload = signer.getPayload(extrinsic, call)
        then:
        Hex.encodeHexString(payload) == "a80500008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480b0030ef7dba02001c0012000000030000004c0bdd177c17ca145ad9a3e76d092d4d4baa8add4fa8c78cc2fbbf8e3cbd51224c0bdd177c17ca145ad9a3e76d092d4d4baa8add4fa8c78cc2fbbf8e3cbd5122"

        when:
        def valid = signer.isValid(extrinsic, call,
                new Extrinsic.SR25519Signature(Hash512.from("0x46176d89b00e11521fba7962ea18e6c4279bc32deda3140b3718f75c2cecba15915c2124cc13767bb6a8fea536788ba23fc40d54d90f8e82ffcb2c59f838808c")),
                TestKeys.alice
        )
        then:
        valid
    }

    def "Sign small amount"() {
        setup:
        ExtrinsicContext extrinsic = ExtrinsicContext.newBuilder()
                .runtime(3, 0x12)
                .genesis(Hash256.from("0x4c0bdd177c17ca145ad9a3e76d092d4d4baa8add4fa8c78cc2fbbf8e3cbd5122"))
                .nonce(7)
                .build()
        BalanceTransfer call = new BalanceTransfer(5, 0).tap {
            destination = TestKeys.bob
            balance = DotAmount.fromPlancks(1)
        }
        ExtrinsicSigner signer = new ExtrinsicSigner<>(new BalanceTransferWriter())
        when:
        def payload = signer.getPayload(extrinsic, call)
        then:
        Hex.encodeHexString(payload) == "900500008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a4804001c0012000000030000004c0bdd177c17ca145ad9a3e76d092d4d4baa8add4fa8c78cc2fbbf8e3cbd51224c0bdd177c17ca145ad9a3e76d092d4d4baa8add4fa8c78cc2fbbf8e3cbd5122"

        when:
        def valid = signer.isValid(extrinsic, call,
                new Extrinsic.SR25519Signature(Hash512.from("0xc6d3033548c4b2752b50da78e936d894d946de79b14be126a9dd61100c736d7a6a66c2973ebc8f65ed969a1de0f9cecdeaf8c22130486a27a875f8b35ce5828c")),
                TestKeys.alice
        )
        then:
        valid
    }

    def "Sign large nonce"() {
        setup:
        ExtrinsicContext extrinsic = ExtrinsicContext.newBuilder()
                .runtime(3, 0x12)
                .genesis(Hash256.from("0x4c0bdd177c17ca145ad9a3e76d092d4d4baa8add4fa8c78cc2fbbf8e3cbd5122"))
                .nonce(1234567890)
                .build()
        BalanceTransfer call = new BalanceTransfer(5, 0).tap {
            destination = TestKeys.bob
            balance = DotAmount.fromDots(123)
        }
        ExtrinsicSigner signer = new ExtrinsicSigner<>(new BalanceTransferWriter())
        when:
        def payload = signer.getPayload(extrinsic, call)
        then:
        Hex.encodeHexString(payload) == "a80500008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480b008cb6611e010003d20296490012000000030000004c0bdd177c17ca145ad9a3e76d092d4d4baa8add4fa8c78cc2fbbf8e3cbd51224c0bdd177c17ca145ad9a3e76d092d4d4baa8add4fa8c78cc2fbbf8e3cbd5122"

        when:
        def valid = signer.isValid(extrinsic, call,
                new Extrinsic.SR25519Signature(Hash512.from("0x98cee3be271b0e127c5142d6823be37bccba77c297c0a1d131c76f9d820d1830be80711b1c86fde8b40f75cd4534666a5b8f41939b4614bfb6dfae1a96d1a88a")),
                TestKeys.alice
        )
        then:
        valid
    }

    def "Sign mortal era"() {
        setup:
        ExtrinsicContext extrinsic = ExtrinsicContext.newBuilder()
                .runtime(3, 0x12)
                .era(new Era.Mortal(32768, 20000))
                .eraBlockHash(Hash256.from("0x4baa8add4fa8c78cc2fbbf8e3cbd51224c0bdd177c17ca145ad9a3e76d092d4d"))
                .genesis(Hash256.from("0x4c0bdd177c17ca145ad9a3e76d092d4d4baa8add4fa8c78cc2fbbf8e3cbd5122"))
                .nonce(7)
                .build()
        BalanceTransfer call = new BalanceTransfer(5, 0).tap {
            destination = TestKeys.bob
            balance = DotAmount.fromDots(300)
        }
        ExtrinsicSigner signer = new ExtrinsicSigner<>(new BalanceTransferWriter())
        when:
        def payload = signer.getPayload(extrinsic, call)
        then:
        Hex.encodeHexString(payload) == "a80500008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480b0030ef7dba024e9c1c0012000000030000004c0bdd177c17ca145ad9a3e76d092d4d4baa8add4fa8c78cc2fbbf8e3cbd51224baa8add4fa8c78cc2fbbf8e3cbd51224c0bdd177c17ca145ad9a3e76d092d4d"
        when:
        def valid = signer.isValid(extrinsic, call,
                new Extrinsic.SR25519Signature(Hash512.from("0xe22aab207ae5cc08c5d4106ff4b8f0c6b6bb2dddbf3b143462d9b1aa8ad8d162a3e78a3d6d656b115fd0756cc61e89943d3eb9a971740ade59938a933f85d58c")),
                TestKeys.alice
        )
        then:
        valid
    }

    def "Validate own signature"() {
        setup:
        ExtrinsicSigner signer = new ExtrinsicSigner<>(new BalanceTransferWriter())
        expect:
        ExtrinsicContext context = ExtrinsicContext.newBuilder()
                .runtime(3, 0x12)
                .genesis(Hash256.from("0x4c0bdd177c17ca145ad9a3e76d092d4d4baa8add4fa8c78cc2fbbf8e3cbd5122"))
                .nonce(nonce)
                .build()
        BalanceTransfer call = new BalanceTransfer(5, 0).tap {
            destination = TestKeys.bob
            balance = DotAmount.fromDots(amount)
        }
        def signature = new Extrinsic.SR25519Signature(signer.sign(context, call, TestKeys.aliceKey))
        signer.isValid(context, call, signature, TestKeys.alice)
        where:
        amount      | nonce
        1.0         | 0
        100.0       | 100
        1.1234      | 256
    }

    def "Validate own ED25519 signature"() {
        setup:
        ExtrinsicSigner signer = new ExtrinsicSigner<>(new BalanceTransferWriter())
        expect:
        ExtrinsicContext context = ExtrinsicContext.newBuilder()
                .runtime(5, 9090)
                .genesis(Hash256.from("0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e"))
                .nonce(1)
                .tip(DotAmount.fromPlancks(7750000718, DotAmount.Westies))
                .build()
        BalanceTransfer call = new BalanceTransfer(4, 3).tap {
            destination = Address.from("5GAiqfv7kwGxnLpCue9pFt7zwt4u1aoYM7p9tHJPGMjNHpEz")
            balance = DotAmount.from(0.5, DotAmount.Westies)
        }
        def signature = new Extrinsic.ED25519Signature(
                Hash512.from("0x634c879c40daf331254bafdbfb24ac3f5286f60d38ed4d056caffd6c5efbd8451fbb0e277f2be832e8e8aad428492c25e8f354f9976500a41e8943284a4e540b"))
        def source = Address.from("5FqBfbPzAD8v8M3XQQEixXJW7HmXZ8JLqLfibxj8zjuPkipz")
        when:
        def valid = signer.isValid(context, call, signature, source)
        then:
        valid
    }
}
