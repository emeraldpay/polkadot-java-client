package io.emeraldpay.polkaj.tx;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import io.emeraldpay.polkaj.scaletypes.EraWriter;
import io.emeraldpay.polkaj.scaletypes.Extrinsic;
import io.emeraldpay.polkaj.scaletypes.ExtrinsicCall;
import io.emeraldpay.polkaj.schnorrkel.Schnorrkel;
import io.emeraldpay.polkaj.schnorrkel.SchnorrkelException;
import io.emeraldpay.polkaj.types.Address;
import io.emeraldpay.polkaj.types.Hash512;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Extrinsic signer and signature verifier. Created with provided SCALE writer for the call type it support, which is
 * used to create a payload for signature.
 *
 * @param <CALL> supported type of the Extrinsic Call
 */
public class ExtrinsicSigner<CALL extends ExtrinsicCall> {

    private final SignaturePayloadWriter<CALL> codec;
    private final SignaturePayloadWriter<CALL> codecAsList;

    /**
     *
     * @param callScaleWriter SCALE coded for the CALL type
     */
    public ExtrinsicSigner(ScaleWriter<CALL> callScaleWriter) {
        this.codec = new SignaturePayloadWriter<>(callScaleWriter, false);
        this.codecAsList = new SignaturePayloadWriter<>(callScaleWriter, true);
    }

    /**
     * Generate a payload for the call
     *
     * @param ctx call context
     * @param call call details
     * @return signature payload
     * @throws SignException if failed to encode call
     */
    public byte[] getPayload(ExtrinsicContext ctx, CALL call) throws SignException {
        return getPayload(ctx, call, true);
    }

    protected byte[] getPayload(ExtrinsicContext ctx, CALL call, boolean asList) throws SignException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        try (ScaleCodecWriter writer = new ScaleCodecWriter(result)) {
            writer.write(asList ? codecAsList : codec, new SignaturePayload<>(ctx, call));
        } catch (IOException e) {
            throw new SignException("Failed to encode signature payload", e);
        }
        byte[] bytes = result.toByteArray();
        if (bytes.length > 256) {
            return Hashing.blake2(bytes);
        } else {
            return bytes;
        }
    }

    /**
     * Create signature for the call
     *
     * @param ctx call context
     * @param call call details
     * @param key key pair
     * @return signature
     * @throws SignException if invalid key or failed to encode
     */
    public Hash512 sign(ExtrinsicContext ctx, CALL call, Schnorrkel.KeyPair key) throws SignException {
        byte[] payload = getPayload(ctx, call, false);
        try {
            return new Hash512(Schnorrkel.getInstance().sign(payload, key));
        } catch (SchnorrkelException e) {
            throw new SignException("Failed to sign", e);
        }
    }

    /**
     * Verify an existing signature agains provided call
     *
     * @param ctx context used to sign call
     * @param call expected call
     * @param signature signature of call
     * @param address signed address
     * @return true if signature is valid under specified context for specified address
     * @throws SignException if invalid key or failed to encode
     */
    public boolean isValid(ExtrinsicContext ctx, CALL call, Extrinsic.Signature signature, Address address)
            throws SignException {
        byte[] payload = getPayload(ctx, call, false);

        Extrinsic.SignatureType signatureType = signature.getType();
        try {
            if (Extrinsic.SignatureType.ED25519 == signatureType) {
                return isValidEd25519Signature(payload, signature, address);
            }
            else {
                return Schnorrkel.getInstance()
                        .verify(signature.getValue().getBytes(), payload, new Schnorrkel.PublicKey(address.getPubkey()));
            }
        }
        catch (SchnorrkelException | SignatureException | NoSuchAlgorithmException | InvalidKeySpecException | IOException | InvalidKeyException e) {
            throw new SignException("Failed to verify", e);
        }
    }

    private boolean isValidEd25519Signature(byte[] payload, Extrinsic.Signature signature, Address address)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException {

    	// register security provider for verification
        final BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);

        // create public key object from address
        SubjectPublicKeyInfo pubKeyInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), address.getPubkey());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKeyInfo.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", bouncyCastleProvider);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        // verify signature
        final var signedData = Signature.getInstance("ed25519", bouncyCastleProvider);
        signedData.initVerify(publicKey);
        signedData.update(payload);
        return signedData.verify(signature.getValue().getBytes());
    }

    public static class SignaturePayload<CALL extends ExtrinsicCall> {
        private final ExtrinsicContext context;
        private final CALL call;

        public SignaturePayload(ExtrinsicContext context, CALL call) {
            this.context = context;
            this.call = call;
        }

        public ExtrinsicContext getContext() {
            return context;
        }

        public CALL getCall() {
            return call;
        }
    }

    public static class SignaturePayloadWriter<CALL extends ExtrinsicCall> implements ScaleWriter<SignaturePayload<CALL>> {

        private static final EraWriter ERA_WRITER = new EraWriter();

        private final ScaleWriter<CALL> callScaleWriter;
        private final boolean callAsList;

        public SignaturePayloadWriter(ScaleWriter<CALL> callScaleWriter, boolean callAsList) {
            this.callScaleWriter = callScaleWriter;
            this.callAsList = callAsList;
        }

        protected byte[] encodeCall(CALL call) throws IOException {
            ByteArrayOutputStream callBuffer = new ByteArrayOutputStream();
            ScaleCodecWriter callWriter = new ScaleCodecWriter(callBuffer);
            callWriter.write(callScaleWriter, call);
            callWriter.close();
            return callBuffer.toByteArray();
        }

        @Override
        public void write(ScaleCodecWriter wrt, SignaturePayload<CALL> signPayload) throws IOException {
            ExtrinsicContext context = signPayload.getContext();
            if (callAsList) {
                wrt.writeAsList(encodeCall(signPayload.getCall()));
            } else {
                wrt.write(callScaleWriter, signPayload.getCall());
            }
            wrt.write(ERA_WRITER, context.getEra().toInteger());
            wrt.write(ScaleCodecWriter.COMPACT_BIGINT, BigInteger.valueOf(context.getNonce()));
            wrt.write(ScaleCodecWriter.COMPACT_BIGINT, context.getTip().getValue());
            wrt.writeUint32(context.getRuntimeVersion());
            wrt.writeUint32(context.getTxVersion());
            wrt.writeUint256(context.getGenesis().getBytes());
            if (context.getEra().isImmortal()) {
                wrt.writeUint256(context.getGenesis().getBytes());
            } else {
                wrt.writeUint256(context.getEraBlockHash().getBytes());
            }
        }
    }
}
