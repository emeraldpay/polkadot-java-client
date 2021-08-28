package io.emeraldpay.polkaj.scaletypes

import io.emeraldpay.polkaj.scale.ScaleCodecReader
import io.emeraldpay.polkaj.scale.UnionValue
import io.emeraldpay.polkaj.ss58.SS58Type
import io.emeraldpay.polkaj.types.Address
import io.emeraldpay.polkaj.types.DotAmount
import io.emeraldpay.polkaj.types.Hash512
import org.apache.commons.codec.binary.Hex
import spock.lang.Specification

class ExtrinsicReaderSpec extends Specification {

    def "Parse transfer"() {
        setup:
        def existing = "41028400b8fdf4f080eeaa6d3f32a445c91c7effa6ffef16d5fe81783837ab7a23602b3b01bc11655de6e7461b0951353db25f4aaf67a58db547fa3a2f20cbcd7772ba715f8ccbe9d8bddf253c7f6e6f6acb83848a7da1f27de248afca10d3291de92ede8ce5000c00040000483eae8765348ef3e347e6b55995f99353223a8b28cf63829554933bcd5e801d0780cff40808"
        ExtrinsicReader<BalanceTransfer> reader = new ExtrinsicReader<>(
                new BalanceTransferReader(SS58Type.Network.CANARY),
                SS58Type.Network.CANARY
        )
        when:
        def rdr = new ScaleCodecReader(Hex.decodeHex(existing))
        def act = reader.read(rdr)

        then:
        with(act.tx) {
            sender == new UnionValue(0, new MultiAddress.AccountID(Address.from("GksmaqmLPbfQhsNgT2S5GcwwTkGXCpkPU8FDzxP4siKPAVu")))
            era == 229
            nonce == 3
            tip == DotAmount.from(0, DotAmount.Kusamas)
            signature.getType() == Extrinsic.SignatureType.SR25519
            signature.getValue() == Hash512.from("0xbc11655de6e7461b0951353db25f4aaf67a58db547fa3a2f20cbcd7772ba715f8ccbe9d8bddf253c7f6e6f6acb83848a7da1f27de248afca10d3291de92ede8c")
        }
        with(act.call) {
            moduleIndex == 4
            callIndex == 0
            destination == new UnionValue(0, new MultiAddress.AccountID(Address.from("ED3aw4s68wTDscCbWnCCw94qSrkA1D8HcUXC8ytaoM2X2xd")))
            balance == DotAmount.from(0.03451, DotAmount.Kusamas)
        }
    }

    def "Parse transfer_keep_alive"() {
        setup:
        def existing = "51028400a6a11c9cf2b58fd914ffc8f667e31e8e6175514833a2892100c8c3bcc904906100634c879c40daf331254bafdbfb24ac3f5286f60d38ed4d056caffd6c5efbd8451fbb0e277f2be832e8e8aad428492c25e8f354f9976500a41e8943284a4e540b0004074ea0efcd01040300b587b6f4e35da071696161b345b378eb282c884a03d23cf7e44ba27cf3f63d4c070088526a74"
        ExtrinsicReader<BalanceTransfer> reader = new ExtrinsicReader<>(
                new BalanceTransferReader(SS58Type.Network.SUBSTRATE),
                SS58Type.Network.SUBSTRATE
        )
        when:
        def rdr = new ScaleCodecReader(Hex.decodeHex(existing))
        def act = reader.read(rdr)

        then:
        with(act.tx) {
            sender == new UnionValue(0, new MultiAddress.AccountID(Address.from("5FqBfbPzAD8v8M3XQQEixXJW7HmXZ8JLqLfibxj8zjuPkipz")))
            era == 0
            nonce == 1
            tip == DotAmount.fromPlancks(7750000718, DotAmount.Westies)
            signature.getType() == Extrinsic.SignatureType.ED25519
            signature.getValue() == Hash512.from("0x634c879c40daf331254bafdbfb24ac3f5286f60d38ed4d056caffd6c5efbd8451fbb0e277f2be832e8e8aad428492c25e8f354f9976500a41e8943284a4e540b")
        }
        with(act.call) {
            moduleIndex == 4
            callIndex == 3
            destination == new UnionValue(0, new MultiAddress.AccountID(Address.from("5GAiqfv7kwGxnLpCue9pFt7zwt4u1aoYM7p9tHJPGMjNHpEz")))
            balance == DotAmount.from(0.5, DotAmount.Westies)
        }
    }
}
