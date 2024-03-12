package io.emeraldpay.polkaj.schnorrkel;

/**
 * Essentially a record to hold the VRF output together with its proof.
 */
public class VrfOutputAndProof {
    public static final int OUTPUT_BYTE_LEN = 32;
    public static final int PROOF_BYTE_LEN = 64;

    private final byte[] output;

    private final byte[] proof;

    public static VrfOutputAndProof wrap(byte[] output, byte[] proof) {
        if (output.length != OUTPUT_BYTE_LEN) {
            throw new IllegalArgumentException(
                String.format("VRF output must be %d bytes (compressed ristretto point).", OUTPUT_BYTE_LEN));
        }

        if (proof.length != PROOF_BYTE_LEN) {
            throw new IllegalArgumentException(
                String.format("VRF proof must be %d bytes (compressed ristretto point).", PROOF_BYTE_LEN));
        }

        return new VrfOutputAndProof(output, proof);
    }

    private VrfOutputAndProof(byte[] output, byte[] proof) {
        this.output = output;
        this.proof = proof;
    }

    public byte[] getOutput() {
        return output;
    }

    public byte[] getProof() {
        return proof;
    }
}
