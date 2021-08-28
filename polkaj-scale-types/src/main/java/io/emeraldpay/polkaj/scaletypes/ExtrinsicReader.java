package io.emeraldpay.polkaj.scaletypes;

import java.util.Arrays;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import io.emeraldpay.polkaj.scale.UnionValue;
import io.emeraldpay.polkaj.scale.reader.UnionReader;
import io.emeraldpay.polkaj.scale.reader.UnsupportedReader;
import io.emeraldpay.polkaj.ss58.SS58Type;
import io.emeraldpay.polkaj.types.DotAmount;
import io.emeraldpay.polkaj.types.Hash512;

public class ExtrinsicReader<CALL extends ExtrinsicCall> implements ScaleReader<Extrinsic<CALL>> {

    private final TransactionInfoReader transactionInfoReader;

    private final ScaleReader<CALL> callScaleReader;

    public ExtrinsicReader(ScaleReader<CALL> callScaleReader, SS58Type.Network network) {
        this.callScaleReader = callScaleReader;
        transactionInfoReader = new TransactionInfoReader(network);
    }

    @Override
    public Extrinsic<CALL> read(ScaleCodecReader rdr) {
        byte[] internal = rdr.readByteArray();
        rdr = new ScaleCodecReader(internal);
        int type = rdr.readByte();
        boolean signed = (Extrinsic.TYPE_BIT_SIGNED & type) > 0;
        int version = Extrinsic.TYPE_UNMASK_VERSION & type;
        if (!signed) {
            throw new IllegalStateException("Trying to read unsigned extrinsic");
        }
        if (version != 4) {
            throw new IllegalStateException("Trying to read unsupported version: " + version);
        }
        Extrinsic<CALL> result = new Extrinsic<>();
        result.setTx(rdr.read(transactionInfoReader));
        result.setCall(rdr.read(callScaleReader));
        return result;
    }

    static class TransactionInfoReader implements ScaleReader<Extrinsic.TransactionInfo> {

        private static final UnionReader<Extrinsic.Signature> SIGNATURE_READER = new UnionReader<>(
                Arrays.asList(
                    new ED25519SignatureReader(),
                    new SR25519SignatureReader(),
                    new UnsupportedReader<>("ECDSA signatures are not supported")
                )
        );
        private static final EraReader ERA_READER = new EraReader();

        private final MultiAddressReader senderReader;

        private final SS58Type.Network network;

        public TransactionInfoReader(SS58Type.Network network) {
            this.senderReader = new MultiAddressReader(network);
            this.network = network;
        }

        @Override
        public Extrinsic.TransactionInfo read(ScaleCodecReader rdr) {
            Extrinsic.TransactionInfo result = new Extrinsic.TransactionInfo();
            result.setSender(rdr.read(senderReader));
            readSignature(result, rdr);
            result.setEra(rdr.read(ERA_READER));
            result.setNonce(rdr.read(ScaleCodecReader.COMPACT_BIGINT).longValueExact());
            result.setTip(new DotAmount(rdr.read(ScaleCodecReader.COMPACT_BIGINT), network));
            return result;
        }

        private void readSignature(Extrinsic.TransactionInfo result, ScaleCodecReader rdr) {
            UnionValue<Extrinsic.Signature> signature = rdr.read(SIGNATURE_READER);
            if (signature != null) {
                result.setSignature(signature.getValue());
            }
        }
    }

    static class SR25519SignatureReader implements ScaleReader<Extrinsic.SR25519Signature> {

        @Override
        public Extrinsic.SR25519Signature read(ScaleCodecReader rdr) {
            return new Extrinsic.SR25519Signature(new Hash512(rdr.readByteArray(64)));
        }
    }

    static class ED25519SignatureReader implements ScaleReader<Extrinsic.ED25519Signature> {

        @Override
        public Extrinsic.ED25519Signature read(ScaleCodecReader rdr) {
            return new Extrinsic.ED25519Signature(new Hash512(rdr.readByteArray(64)));
        }
    }
}
