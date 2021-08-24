package io.emeraldpay.polkaj.api

import spock.lang.Specification

import java.util.concurrent.ExecutionException

class PolkadotApiSpec extends Specification{

    RpcCallAdapter rpcCallAdapter = Mock()
    SubscriptionAdapter subscriptionAdapter = Mock()
    Runnable onClose = Mock()

    def "close is passed to all listeners"(){
        setup:
        def polkadotApi = PolkadotApi.newBuilder()
                .subscriptionAdapter(subscriptionAdapter)
                .rpcCallAdapter(rpcCallAdapter)
                .onClose(onClose)
                .build()
        when:
        polkadotApi.close()
        then:
        1 * rpcCallAdapter.close()
        1 * subscriptionAdapter.close()
        1 * onClose.run()
    }

    def "does not call close twice on subscriptionAdapter"(){
        setup:
        def polkadotApi = PolkadotApi.newBuilder()
                .subscriptionAdapter(subscriptionAdapter)
                .onClose(onClose)
                .build()
        when:
        polkadotApi.close()
        then:
        1 * subscriptionAdapter.close()
        1 * onClose.run()
    }

    def "uses RpcCallAdapter when call is executed"(){
        setup:
        def polkadotApi = PolkadotApi.newBuilder()
                .rpcCallAdapter(rpcCallAdapter)
                .onClose(onClose)
                .build()
        def call = RpcCall.create(String, "test")
        when:
        polkadotApi.execute(call)
        then:
        1 * rpcCallAdapter.produceRpcFuture(call)
    }

    def "uses SubscriptionAdapter for RPC calls"(){
        setup:
        def polkadotApi = PolkadotApi.newBuilder()
                .subscriptionAdapter(subscriptionAdapter)
                .onClose(onClose)
                .build()
        def call = RpcCall.create(String, "test")
        when:
        polkadotApi.execute(call)
        then:
        1 * subscriptionAdapter.produceRpcFuture(call)
    }

    def "uses SubscriptionAdapter when subscribed"(){
        setup:
        def polkadotApi = PolkadotApi.newBuilder()
                .subscriptionAdapter(subscriptionAdapter)
                .onClose(onClose)
                .build()
        def call = SubscribeCall.create(String, "test", "test")
        when:
        polkadotApi.subscribe(call)
        then:
        1 * subscriptionAdapter.subscribe(call)
    }

    def "execution when closed causes exception"(){
        setup:
        def polkadotApi = PolkadotApi.newBuilder()
                .rpcCallAdapter(rpcCallAdapter)
                .onClose(onClose)
                .build()
        def call = RpcCall.create(String, "test")
        polkadotApi.close()
        when:
        polkadotApi.execute(call).get()
        then:
        def t = thrown(ExecutionException)
        t.cause instanceof IllegalStateException
        0 * rpcCallAdapter.produceRpcFuture(call)
    }

    def "execution when closed causes exeption subscribe adapter"(){
        setup:
        def polkadotApi = PolkadotApi.newBuilder()
                .subscriptionAdapter(subscriptionAdapter)
                .onClose(onClose)
                .build()
        def call = RpcCall.create(String, "test")
        polkadotApi.close()
        when:
        polkadotApi.execute(call).get()
        then:
        def t = thrown(ExecutionException)
        t.cause instanceof IllegalStateException
        0 * subscriptionAdapter.produceRpcFuture(call)
    }

    def "subscription when closed causes exeption"(){
        setup:
        def polkadotApi = PolkadotApi.newBuilder()
                .subscriptionAdapter(subscriptionAdapter)
                .onClose(onClose)
                .build()
        def call = SubscribeCall.create(String, "test", "test")
        polkadotApi.close()
        when:
        polkadotApi.subscribe(call).get()
        then:
        def t = thrown(ExecutionException)
        t.cause instanceof IllegalStateException
        0 * subscriptionAdapter.subscribe(call)
    }

    def "throws exception when no adapter set on subscribe"(){
        setup:
        def polkadotApi = PolkadotApi.newBuilder()
                .onClose(onClose)
                .build()
        def call = SubscribeCall.create(String, "test", "test")
        when:
        polkadotApi.subscribe(call).get()
        then:
        def t = thrown(ExecutionException)
        t.cause instanceof IllegalStateException
    }

    def "throws exception no no adapter set on execute"(){
        setup:
        def polkadotApi = PolkadotApi.newBuilder()
                .onClose(onClose)
                .build()
        def call = RpcCall.create(String, "test")
        when:
        polkadotApi.execute(call).get()
        then:
        def t = thrown(ExecutionException)
        t.cause instanceof IllegalStateException
    }

    def "returns StandardCommands shortcut"(){
        assert PolkadotApi.commands() == StandardCommands.getInstance();
    }
}
