package io.emeraldpay.polkaj.scaletypes;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import io.emeraldpay.polkaj.ss58.SS58Type;

public class AccountDataReader implements ScaleReader<AccountData> {

    private final SS58Type.Network network;

    public AccountDataReader(SS58Type.Network network) {
        this.network = network;
    }

    @Override
    public AccountData read(ScaleCodecReader rdr) {
        AccountData result = new AccountData();
        BalanceReader balanceReader = new BalanceReader(network);
        result.setFree(rdr.read(balanceReader));
        result.setReserved(rdr.read(balanceReader));
        result.setMiscFrozen(rdr.read(balanceReader));
        result.setFeeFrozen(rdr.read(balanceReader));
        return result;
    }
}
