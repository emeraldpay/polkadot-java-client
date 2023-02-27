package io.emeraldpay.polkaj.scaletypes;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;

import java.io.IOException;

public class ResultWriter<T, E> {
    public void writeResult(ScaleCodecWriter writer, ScaleWriter<T> okScaleWriter,
                            ScaleWriter<E> errorScaleWriter, Result<T, E> result) throws IOException {
        writer.writeByte(result.mode.getValue());
        if (result.mode == Result.ResultMode.OK) {
            writer.write(okScaleWriter, result.ok);
            return;
        }
        writer.write(errorScaleWriter, result.error);
    }
}
