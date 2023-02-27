package io.emeraldpay.polkaj.scaletypes;


public class Result<T, E> {

    public enum ResultMode {
        OK((byte) 0), ERR((byte) 1);
        private byte value;

        ResultMode(byte value) {
            this.value = value;
        }

        public byte getValue() {
            return this.value;
        }
    }

    T ok;
    E error;
    ResultMode mode;

    public Result(ResultMode mode, T ok, E error) {
        this.mode = mode;
        this.ok = ok;
        this.error = error;
    }

    public boolean isOk() {
        return mode == ResultMode.OK;
    }

    public boolean isError() {
        return mode == ResultMode.ERR;
    }

    public T getOkValue() {
        return ok;
    }

    public E getErrorValue() {
        return error;
    }
}
