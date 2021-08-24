package io.emeraldpay.polkaj.api;

import java.util.concurrent.CompletableFuture;

/**
 * @see PolkadotMethod
 */
public interface PolkadotApi extends AutoCloseable {

    /**
     * Execute JSON RPC request
     *
     * @param call call details to execute
     * @param <T> type of the result
     * @return CompletableFuture for the result. Note that the Future may throw RpcException when it get
     * @see RpcException
     */
    <T> CompletableFuture<T> execute(RpcCall<T> call);

    /**
     * Subscribe to a method that provides multiple responses
     *
     * @param call subscription call details to execute
     * @param <T> type of the result
     * @return Subscription instance
     */
    <T> CompletableFuture<Subscription<T>> subscribe(SubscribeCall<T> call);

    /**
     *
     * @return Standard Polkadot RPC commands
     */
    static StandardCommands commands() {
        return StandardCommands.getInstance();
    }

    static Builder newBuilder(){
        return new Builder();
    }

    class Builder {

        private Runnable onClose;
        private RpcCallAdapter rpcCallAdapter;
        private SubscriptionAdapter subscriptionAdapter;

        public Builder rpcCallAdapter(RpcCallAdapter adapter){
            this.rpcCallAdapter = adapter;
            return this;
        }

        public Builder subscriptionAdapter(SubscriptionAdapter adapter){
            this.rpcCallAdapter = adapter;
            this.subscriptionAdapter = adapter;
            return this;
        }

        public Builder onClose(Runnable onClose) {
            this.onClose = onClose;
            return this;
        }

        /**
         * Apply configuration and build client
         *
         * @return new instance of PolkadotRpcClient
         */
        public PolkadotApi build() {
            return new PolkadotApiImpl(onClose, rpcCallAdapter, subscriptionAdapter);
        }
    }


}
