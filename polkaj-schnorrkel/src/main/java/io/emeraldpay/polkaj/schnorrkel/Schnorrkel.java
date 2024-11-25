package io.emeraldpay.polkaj.schnorrkel;

import io.emeraldpay.polkaj.merlin.TranscriptData;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Schnorrkel implements Schnorr signature on Ristretto compressed Ed25519 points, as well as related protocols like
 * HDKD, MuSig, and a verifiable random function (VRF).
 * <br>
 * See also:
 * <ul>
 *     <li><a href="https://tools.ietf.org/html/rfc8032">RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)</a></li>
 * </ul>
 */
public abstract class Schnorrkel {

    private static final SchnorrkelNative NATIVE_INSTANCE = new SchnorrkelNative();

    public static Schnorrkel getInstance() {
        return NATIVE_INSTANCE;
    }

    /**
     * The length of the "key" portion of a Ristretto Schnorr secret key, in bytes.
     */
    public static final int SECRET_KEY_MAIN_LENGTH = 32;

    /**
     * The length of the "nonce" portion of a Ristretto Schnorr secret key, in bytes.
     */
    public static final int SECRET_KEY_NONCE_LENGTH = 32;

    /**
     * The length of a Ristretto Schnorr `PublicKey`, in bytes.
     */
    public static final int PUBLIC_KEY_LENGTH = 32;

    /**
     * The length of a Ristretto Schnorr key, `SecretKey`, in bytes.
     */
    public static final int SECRET_KEY_LENGTH = SECRET_KEY_MAIN_LENGTH + SECRET_KEY_NONCE_LENGTH;

    /**
     * The length of an Ristretto Schnorr `Keypair`, in bytes.
     */
    public static final int KEYPAIR_LENGTH = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

    /**
     * Length in bytes of chain codes
     */
    public static final int CHAIN_CODE_LENGTH = 32;

    // ====================== Methods ======================

    /**
     * Sign message
     *
     * @param message source message
     * @param keypair secret key pair of the signer
     * @return public signature
     *
     * @throws SchnorrkelException when secret key is invalid
     */
    public abstract byte[] sign(byte[] message, Schnorrkel.KeyPair keypair) throws SchnorrkelException;

    /**
     * Verify signature
     *
     * @param signature signature
     * @param message signed message
     * @param publicKey public key of the signer
     * @return true if signature is correct
     * @throws SchnorrkelException when signature or public key are invalid
     */
    public abstract boolean verify(byte[] signature, byte[] message, Schnorrkel.PublicKey publicKey) throws SchnorrkelException;

    /**
     * Generate a new Key Pair using default Secure Random source
     *
     * @return new Key Pair
     * @throws SchnorrkelException is Secure Random is not available
     */
    public abstract Schnorrkel.KeyPair generateKeyPair() throws SchnorrkelException;

    /**
     * Generate a new Key Pair
     *
     * @param random provide a Secure Random for key generation
     * @return new Key Pair
     * @throws SchnorrkelException if failed to generate from the source of random
     */
    public abstract Schnorrkel.KeyPair generateKeyPair(SecureRandom random) throws SchnorrkelException;

    /**
     * Generate a new Key Pair from provided seed
     *
     * @param seed seed value
     * @return new Key Pair
     * @throws SchnorrkelException if seed is invalid
     */
    public abstract Schnorrkel.KeyPair generateKeyPairFromSeed(byte[] seed) throws SchnorrkelException;

    /**
     * Derive a new Key Pair from existing.
     *
     * @param base current Key Pair
     * @param chainCode derivation path
     * @return new Key Pair
     * @throws SchnorrkelException if Key Pair or Derivation Path are invalid
     */
    public abstract Schnorrkel.KeyPair deriveKeyPair(Schnorrkel.KeyPair base, Schnorrkel.ChainCode chainCode) throws SchnorrkelException;

    /**
     * Derive a new Key Pair from existing, using Soft algorithm (which allows to generate Public key separately)
     *
     * @param base current Key Pair
     * @param chainCode derivation path
     * @return new Key Pair
     * @throws SchnorrkelException if Key Pair or Derivation Path are invalid
     */
    public abstract Schnorrkel.KeyPair deriveKeyPairSoft(Schnorrkel.KeyPair base, Schnorrkel.ChainCode chainCode) throws SchnorrkelException;

    /**
     * Derive a new Public Key from existing
     *
     * @param base existing Public Key
     * @param chainCode derivation path
     * @return new Public Key
     * @throws SchnorrkelException if Public Key or Derivation Path are invalid
     */
    public abstract Schnorrkel.PublicKey derivePublicKeySoft(Schnorrkel.PublicKey base, Schnorrkel.ChainCode chainCode) throws SchnorrkelException;

    public abstract boolean vrfVerify(PublicKey sk, TranscriptData transcript, VrfOutputAndProof vrfOutputAndProof);

    public abstract VrfOutputAndProof vrfSign(KeyPair keyPair, TranscriptData transcript);

    public abstract byte[] makeBytes(Schnorrkel.PublicKey publicKey, TranscriptData transcript, VrfOutputAndProof vrfOutputAndProof);

    // ====================== Supporting Classes ======================

    /**
     * Public Key
     */
    public static class PublicKey {

        private final byte[] publicKey;

        public PublicKey(byte[] publicKey) {
            this.publicKey = publicKey;
        }
        public byte[] getPublicKey() {
            return publicKey;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof PublicKey)) return false;
            if (o instanceof KeyPair) return false;
            PublicKey publicKey1 = (PublicKey) o;
            return Arrays.equals(publicKey, publicKey1.publicKey);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(publicKey);
        }
    }

    /**
     * Pair of Public and Secret Keys
     */
    public static class KeyPair extends PublicKey {

        private final byte[] secretKey;

        public KeyPair(PublicKey publicKey, byte[] secretKey) {
            this(publicKey.publicKey, secretKey);
        }

        public KeyPair(byte[] publicKey, byte[] secretKey) {
            super(publicKey);
            this.secretKey = secretKey;
        }

        public byte[] getSecretKey() {
            return secretKey;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof KeyPair)) return false;
            KeyPair keyPair = (KeyPair) o;
            return Arrays.equals(getPublicKey(), keyPair.getPublicKey())
                    && Arrays.equals(secretKey, keyPair.secretKey);
        }

        @Override
        public int hashCode() {
            int result = super.hashCode();
            result = 31 * result + Arrays.hashCode(secretKey);
            return result;
        }
    }

    public static class ChainCode {
        private final byte[] value;

        public ChainCode(byte[] value) {
            if (value.length != CHAIN_CODE_LENGTH) {
                throw new IllegalArgumentException("Chain code must be " + CHAIN_CODE_LENGTH + " bytes");
            }
            this.value = value;
        }

        public static ChainCode from(byte[] value) {
            if (value.length > CHAIN_CODE_LENGTH) {
                throw new IllegalArgumentException("Chain code must be " + CHAIN_CODE_LENGTH + " bytes (if less, then padded with zeroes)");
            }
            if (value.length == CHAIN_CODE_LENGTH) {
                return new ChainCode(value);
            }
            byte[] full = new byte[CHAIN_CODE_LENGTH];
            System.arraycopy(value, 0, full, 0, value.length);
            return new ChainCode(full);
        }

        public byte[] getValue() {
            return value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof ChainCode)) return false;
            ChainCode chainCode = (ChainCode) o;
            return Arrays.equals(value, chainCode.value);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(value);
        }
    }
}
