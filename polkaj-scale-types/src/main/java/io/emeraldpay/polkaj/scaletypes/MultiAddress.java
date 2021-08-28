package io.emeraldpay.polkaj.scaletypes;

import java.util.Objects;

import io.emeraldpay.polkaj.scale.UnionValue;
import io.emeraldpay.polkaj.types.Address;

/**
 * Represents the MultiAddress enum defined in Substrate
 *
 * See: https://github.com/paritytech/substrate/blob/master/primitives/runtime/src/multiaddress.rs
 */
public abstract class MultiAddress {

    public enum Type {
        ID(0),
        INDEX(1),
        RAW(2),
        ADDRESS32(3),
        ADDRESS20(4);

        private final int code;

        Type(int code) {
            this.code = code;
        }

        public int getCode() {
            return code;
        }
    }

    /**
     * Helper to create a UnionValue from a concrete MultiAddress instance
     *
     * @param type a valid MultiAddress.Type constant
     * @param value concrete MultiAddress instance
     * @return
     */
    public static UnionValue<MultiAddress> from(int type, MultiAddress value) {
        return new UnionValue<>(type, value);
    }

    /**
     * First MultiAddress type, used as a wrapper of a standard Address object
     */
    public static class AccountID extends MultiAddress {

        private final Address address;

        public AccountID(Address address) {
            this.address = address;
        }

        public Address getAddress() {
            return address;
        }

        /**
         * Transforms a standard Address object into a fully wrapped MultiAddress UnionValue
         */
        public static UnionValue<MultiAddress> from(Address address) {
            return MultiAddress.from(Type.ID.getCode(), new AccountID(address));
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof AccountID)) return false;
            if (!((AccountID)o).canEquals(this)) return false;
            AccountID that = (AccountID) o;
            return Objects.equals(address, that.address);
        }

        @Override
        public int hashCode() {
            return Objects.hash(address);
        }

        public boolean canEquals(Object o) {
            return (o instanceof AccountID);
        }

        @Override
        public String toString() {
            return "AccountID{" +
                    "address=" + address +
                    '}';
        }
    }
}
