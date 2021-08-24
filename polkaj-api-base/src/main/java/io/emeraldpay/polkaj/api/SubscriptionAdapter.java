package io.emeraldpay.polkaj.api;

import java.util.concurrent.CompletableFuture;

/**
 * @see PolkadotMethod
 */
public interface SubscriptionAdapter extends RpcCallAdapter{


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
     * @return Standard Polkadot RPC subscriptions
     */
    public static StandardSubscriptions subscriptions() {
        return StandardSubscriptions.getInstance();
    }


}
