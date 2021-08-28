package io.emeraldpay.polkaj.scaletypes;

import java.util.Objects;

import io.emeraldpay.polkaj.types.DotAmount;

public class AccountData {

    private DotAmount free;
    private DotAmount reserved;
    private DotAmount miscFrozen;
    private DotAmount feeFrozen;

    public DotAmount getFree() {
        return free;
    }

    public void setFree(DotAmount free) {
        this.free = free;
    }

    public DotAmount getReserved() {
        return reserved;
    }

    public void setReserved(DotAmount reserved) {
        this.reserved = reserved;
    }

    public DotAmount getMiscFrozen() {
        return miscFrozen;
    }

    public void setMiscFrozen(DotAmount miscFrozen) {
        this.miscFrozen = miscFrozen;
    }

    public DotAmount getFeeFrozen() {
        return feeFrozen;
    }

    public void setFeeFrozen(DotAmount feeFrozen) {
        this.feeFrozen = feeFrozen;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AccountData)) return false;
        AccountData that = (AccountData) o;
        return Objects.equals(free, that.free) &&
                Objects.equals(reserved, that.reserved) &&
                Objects.equals(miscFrozen, that.miscFrozen) &&
                Objects.equals(feeFrozen, that.feeFrozen);
    }

    @Override
    public int hashCode() {
        return Objects.hash(free, reserved, miscFrozen, feeFrozen);
    }

    @Override
    public String toString() {
        return "AccountData{" +
                "free=" + free +
                ", reserved=" + reserved +
                ", miscFrozen=" + miscFrozen +
                ", feeFrozen=" + feeFrozen +
                '}';
    }
}
