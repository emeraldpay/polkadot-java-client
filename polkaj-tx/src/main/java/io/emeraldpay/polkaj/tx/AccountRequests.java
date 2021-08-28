package io.emeraldpay.polkaj.tx;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scaletypes.AccountInfo;
import io.emeraldpay.polkaj.scaletypes.AccountInfoReader;
import io.emeraldpay.polkaj.scaletypes.BalanceReader;
import io.emeraldpay.polkaj.scaletypes.BalanceTransfer;
import io.emeraldpay.polkaj.scaletypes.BalanceTransferWriter;
import io.emeraldpay.polkaj.scaletypes.Extrinsic;
import io.emeraldpay.polkaj.scaletypes.ExtrinsicWriter;
import io.emeraldpay.polkaj.scaletypes.Metadata;
import io.emeraldpay.polkaj.schnorrkel.Schnorrkel;
import io.emeraldpay.polkaj.ss58.SS58Type;
import io.emeraldpay.polkaj.types.Address;
import io.emeraldpay.polkaj.types.ByteData;
import io.emeraldpay.polkaj.types.DotAmount;

/**
 * Common requests and extrinsics specific to accounts.
 */
public class AccountRequests {

    /**
     * Get total blockchain issuance
     * @return total issuance reader
     */
    public static TotalIssuance totalIssuance() {
        return new TotalIssuance();
    }

    /**
     * Get current balance
     *
     * @param address address
     * @return balance reader
     */
    public static AddressBalance balanceOf(Address address) {
        return new AddressBalance(address);
    }

    /**
     * Transfer value from one account to another
     * @return builder for transfer
     */
    public static TransferBuilder transfer() {
        return new TransferBuilder();
    }

    /**
     * Transfer value from one account to another, but making sure that the balance of both accounts is above the existential
     * deposit
     *
     * @return builder for transfer-keep-alive
     */
    public static TransferKeepAliveBuilder transferKeepAlive() {
        return new TransferKeepAliveBuilder();
    }

    public static class TotalIssuance extends StorageRequest<DotAmount> {

        @Override
        public ByteData encodeRequest() {
            String key1 = "Balances";
            String key2 = "TotalIssuance";
            int len = 16 + 16;
            ByteBuffer buffer = ByteBuffer.allocate(len);
            Hashing.xxhash128(buffer, key1);
            Hashing.xxhash128(buffer, key2);
            return new ByteData(buffer.flip().array());
        }

        @Override
        public DotAmount apply(ByteData result) {
            return new ScaleCodecReader(result.getBytes()).read(new BalanceReader());
        }
    }

    public static class AddressBalance extends StorageRequest<AccountInfo> {

        private final Address address;

        public AddressBalance(Address address) {
            this.address = address;
        }

        @Override
        public ByteData encodeRequest() {
            String key1 = "System";
            String key2 = "Account";
            int len = 16 + 16 + 16 + 32;
            ByteBuffer buffer = ByteBuffer.allocate(len);
            Hashing.xxhash128(buffer, key1);
            Hashing.xxhash128(buffer, key2);
            Hashing.blake2128(buffer, address);
            buffer.put(address.getPubkey());
            return new ByteData(buffer.flip().array());
        }

        @Override
        public AccountInfo apply(ByteData result) {
            if (result == null) {
                return null;
            }
            return new ScaleCodecReader(result.getBytes()).read(new AccountInfoReader(address.getNetwork()));
        }
    }

    public static class Transfer implements ExtrinsicRequest {
        private static final ExtrinsicWriter<BalanceTransfer> CODEC = new ExtrinsicWriter<>(
                new BalanceTransferWriter()
        );

        private final Extrinsic<BalanceTransfer> extrinsic;

        public Transfer(Extrinsic<BalanceTransfer> extrinsic) {
            this.extrinsic = extrinsic;
        }

        public Extrinsic<BalanceTransfer> getExtrinsic() {
            return extrinsic;
        }

        @Override
        public ByteData encodeRequest() throws IOException {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            ScaleCodecWriter writer = new ScaleCodecWriter(buf);
            writer.write(CODEC, extrinsic);
            return new ByteData(buf.toByteArray());
        }

        @Override
        public String toString() {
            return "Transfer{" +
                    "extrinsic=" + extrinsic +
                    '}';
        }
    }


    public static class TransferBuilder {
        private Address from;
        private Extrinsic.Signature signature;
        private Long nonce;
        private DotAmount tip;

        protected final BalanceTransfer call = new BalanceTransfer();

        public TransferBuilder runtime(Metadata metadata) {
            this.call.init(metadata);
            return this;
        }

        /**
         * Set call details
         *
         * @param moduleIndex module index
         * @param callIndex call index in the module
         * @return builder
         */
        public TransferBuilder module(int moduleIndex, int callIndex) {
            call.setModuleIndex(moduleIndex);
            call.setCallIndex(callIndex);
            return this;
        }

        /**
         *
         * @param from sender address
         * @return builder
         */
        public TransferBuilder from(Address from) {
            this.from = from;
            if (this.tip == null) {
                // set default tip as well now that the network is known
                this.tip = new DotAmount(BigInteger.ZERO, from.getNetwork());
            }
            return this;
        }

        /**
         *
         * @param to recipient address
         * @return builder
         */
        public TransferBuilder to(Address to) {
            this.call.setDestination(to);
            return this;
        }

        /**
         *
         * @param amount amount to transfer
         * @return builder
         */
        public TransferBuilder amount(DotAmount amount) {
            this.call.setBalance(amount);
            return this;
        }

        /**
         * (optional) tip to include for the miner
         *
         * @param tip tip to use
         * @return builder
         */
        public TransferBuilder tip(DotAmount tip) {
            this.tip = tip;
            return this;
        }

        /**
         * (optional) Set once, if setting a predefined signature.
         * Otherwise, nonce is set during {@link #sign} operation
         *
         * @param nonce once to use
         * @return builder
         */
        public TransferBuilder nonce(Long nonce) {
            this.nonce = nonce;
            return this;
        }

        /**
         * (optional) Set once provided with the context, if setting a presefined signature.
         * Otherwise nonce is set during {@link #sign} operation
         *
         * @param context context with once to use
         * @return builder
         */
        public TransferBuilder nonce(ExtrinsicContext context) {
            return nonce(context.getNonce());
        }

        /**
         * Set a predefined signature. Either this method, or {@link #sign} must be called
         *
         * @param signature precalculated signature
         * @return builder
         */
        public TransferBuilder signed(Extrinsic.Signature signature) {
            this.signature = signature;
            return this;
        }

        /**
         * Sign the transfer
         *
         * @param key sender key pair
         * @param context signing context
         * @return builder
         * @throws SignException if signing is failed
         * @throws IllegalStateException on data conflict
         */
        public TransferBuilder sign(Schnorrkel.KeyPair key, ExtrinsicContext context) throws SignException {
            if (this.nonce != null && this.nonce != context.getNonce()) {
                throw new IllegalStateException("Trying to sign with context with different nonce. Reset nonce, or provide the same value");
            }
            if (this.from != null) {
                if (!Arrays.equals(this.from.getPubkey(), key.getPublicKey())) {
                    throw new SignException("Cannot sign transfer from " + this.from + " by pubkey of " + new Address(this.from.getNetwork(), key.getPublicKey()));
                }
            } else {
                this.from = new Address(SS58Type.Network.LIVE, key.getPublicKey());
            }
            ExtrinsicSigner<BalanceTransfer> signer = new ExtrinsicSigner<>(new BalanceTransferWriter());
            return this.nonce(context)
                    .signed(new Extrinsic.SR25519Signature(signer.sign(context, this.call, key)));
        }

        /**
         *
         * @return signed Transfer
         */
        public Transfer build() {
            Extrinsic.TransactionInfo tx = new Extrinsic.TransactionInfo();
            tx.setNonce(this.nonce);
            tx.setSender(this.from);
            tx.setSignature(buildSignature(this.signature));
            tx.setTip(this.tip);

            Extrinsic<BalanceTransfer> extrinsic = new Extrinsic<>();
            extrinsic.setCall(this.call);
            extrinsic.setTx(tx);
            return new Transfer(extrinsic);
        }

        private Extrinsic.Signature buildSignature(Extrinsic.Signature signature) {
            switch (signature.getType()) {
                case ED25519:
                    return new Extrinsic.ED25519Signature(signature.getValue());
                case SR25519:
                    return new Extrinsic.SR25519Signature(signature.getValue());
                default:
                    String msg = String.format("Signature type %s is not supported", signature.getType());
                    throw new UnsupportedOperationException(msg);
            }
        }
    }

    public static final class TransferKeepAliveBuilder extends TransferBuilder {

        private static final String TRANSFER_KEEP_ALIVE = "transfer_keep_alive";

        @Override
        public TransferBuilder runtime(Metadata metadata) {
            this.call.init(metadata, TRANSFER_KEEP_ALIVE);
            return this;
        }
    }

}
