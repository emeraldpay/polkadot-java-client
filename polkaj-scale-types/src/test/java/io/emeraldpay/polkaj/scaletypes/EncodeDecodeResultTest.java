package io.emeraldpay.polkaj.scaletypes;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.jupiter.api.Assertions;

public class EncodeDecodeResultTest {

    @Test
    public void EncodeDecodeResultTest() {
        Result<Integer, Integer> dataToEncode = new Result<>(Result.ResultMode.OK, 10, 5);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (ScaleCodecWriter writer = new ScaleCodecWriter(buf)) {
            ResultWriter<Integer, Integer> resultWriter = new ResultWriter();
            resultWriter.writeResult(writer, ScaleCodecWriter::writeCompact, ScaleCodecWriter::writeCompact, dataToEncode);

            byte[] decodeBuf = buf.toByteArray();
            ScaleCodecReader reader = new ScaleCodecReader(decodeBuf);
            ResultReader<Integer, Integer> resultReader = new ResultReader<>();
            Result<Integer, Integer> result = resultReader.readResult(reader, ScaleCodecReader::readCompactInt, ScaleCodecReader::readCompactInt);

            Assertions.assertEquals(dataToEncode.mode, result.mode);
            Assertions.assertEquals(dataToEncode.getOkValue(), result.getOkValue());
            Assertions.assertEquals(null, result.getErrorValue());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
