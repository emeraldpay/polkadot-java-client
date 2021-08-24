package io.emeraldpay.polkaj.api;

import java.util.concurrent.CompletableFuture;


final class PolkadotApiImpl implements PolkadotApi {

    private boolean closed = false;

    private final Runnable onClose;
    private final RpcCallAdapter rpcCallAdapter;
    private final SubscriptionAdapter subcriptionAdapter;

    public PolkadotApiImpl(Runnable onClose,
                           RpcCallAdapter rpcCallAdapter,
                           SubscriptionAdapter subscriptionAdapter) {
        this.onClose = onClose;
        this.rpcCallAdapter = rpcCallAdapter;
        this.subcriptionAdapter = subscriptionAdapter;
    }

    @Override
    public <T> CompletableFuture<T> execute(RpcCall<T> call) {
        if (closed) {
            CompletableFuture<T> future = new CompletableFuture<>();
            future.completeExceptionally(new IllegalStateException("Client is already closed"));
            return future;
        }
        if(rpcCallAdapter == null){
            CompletableFuture<T> future = new CompletableFuture<>();
            future.completeExceptionally(new IllegalStateException("RpcCallAdapter Not set"));
            return future;
        }

        return rpcCallAdapter.produceRpcFuture(call);
    }

    @Override
    public <T> CompletableFuture<Subscription<T>> subscribe(SubscribeCall<T> call) {
        if (closed) {
            CompletableFuture<Subscription<T>> future = new CompletableFuture<>();
            future.completeExceptionally(new IllegalStateException("Client is already closed"));
            return future;
        }
        if(subcriptionAdapter == null){
            CompletableFuture<Subscription<T>> future = new CompletableFuture<>();
            future.completeExceptionally(new IllegalStateException("SubscriptionAdapter Not set"));
            return future;
        }
        return subcriptionAdapter.subscribe(call);
    }

    @Override
    public void close() throws Exception {
        if(closed) return;
        closed = true;
        if(rpcCallAdapter != null) rpcCallAdapter.close();
        if(subcriptionAdapter != null && subcriptionAdapter != rpcCallAdapter) subcriptionAdapter.close();
        if(onClose != null) onClose.run();
    }
}
