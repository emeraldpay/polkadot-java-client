package io.emeraldpay.polkaj.scaletypes

import io.emeraldpay.polkaj.scale.ScaleCodecReader
import io.emeraldpay.polkaj.ss58.SS58Type
import io.emeraldpay.polkaj.types.DotAmount
import org.apache.commons.codec.binary.Hex
import spock.lang.Specification

class BalanceReaderSpec extends Specification {

    def "Read values"() {
        BalanceReader reader = new BalanceReader()

        expect:
        new ScaleCodecReader(Hex.decodeHex(hex)).read(reader) == balance
        where:
        hex                                 | balance
        "f70af5f6f3c843050000000000000000"  | DotAmount.fromPlancks("379367743775116023")
        "0000c52ebca2b1000000000000000000"  | DotAmount.fromDots(5000000)
        "00000000000000000000000000000000"  | DotAmount.ZERO
    }

    def "Read values (Kusama)"() {
        BalanceReader reader = new BalanceReader(SS58Type.Network.CANARY)

        expect:
        new ScaleCodecReader(Hex.decodeHex(hex)).read(reader) == balance
        where:
        hex                                 | balance
        "f70af5f6f3c843050000000000000000"  | DotAmount.fromPlancks(379367743775116023L, DotAmount.Kusamas)
        "0000c52ebca2b1000000000000000000"  | DotAmount.from(50000, DotAmount.Kusamas)
        "00000000000000000000000000000000"  | DotAmount.from(0, DotAmount.Kusamas)
    }

    def "Read values (Westend)"() {
        BalanceReader reader = new BalanceReader(SS58Type.Network.SUBSTRATE)

        expect:
        new ScaleCodecReader(Hex.decodeHex(hex)).read(reader) == balance
        where:
        hex                                 | balance
        "f70af5f6f3c843050000000000000000"  | DotAmount.fromPlancks(379367743775116023L, DotAmount.Westies)
        "0000c52ebca2b1000000000000000000"  | DotAmount.from(50000, DotAmount.Westies)
        "00000000000000000000000000000000"  | DotAmount.from(0, DotAmount.Westies)
    }
}
