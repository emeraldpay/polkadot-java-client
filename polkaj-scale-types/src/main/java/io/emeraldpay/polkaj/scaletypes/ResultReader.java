package io.emeraldpay.polkaj.scaletypes;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;

public class ResultReader<T, E> {
    static final String unsupportedValueMessage = "Reading unsupported result mode value";

    public Result<T, E> readResult(ScaleCodecReader reader, ScaleReader<T> okScaleReader, ScaleReader<E> errorScaleReader) {
        byte mode = reader.readByte();
        if (mode == Result.ResultMode.OK.getValue()) {
            T ok = reader.read(okScaleReader);
            return new Result(Result.ResultMode.OK, ok, null);
        }
        if (mode == Result.ResultMode.ERR.getValue()) {
            E error = reader.read(errorScaleReader);
            return new Result(Result.ResultMode.ERR, null, error);
        }
        throw new IllegalStateException(unsupportedValueMessage);
    }
}
