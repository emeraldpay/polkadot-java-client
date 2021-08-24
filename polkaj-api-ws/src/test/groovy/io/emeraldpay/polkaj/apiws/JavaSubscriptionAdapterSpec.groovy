package io.emeraldpay.polkaj.apiws

import com.fasterxml.jackson.databind.ObjectMapper
import io.emeraldpay.polkaj.api.MockWsServer
import io.emeraldpay.polkaj.api.PolkadotApi
import io.emeraldpay.polkaj.api.RpcCall
import io.emeraldpay.polkaj.api.RpcCoder
import io.emeraldpay.polkaj.api.SubscriptionAdapter
import io.emeraldpay.polkaj.api.SubscriptionAdapterSpec

import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit

class JavaSubscriptionAdapterSpec extends SubscriptionAdapterSpec {

    // needs large timeouts and sleep, especially on CI where it's much slower to run
    static TIMEOUT = 15
    static SLEEP = 250

    @Override
    SubscriptionAdapter provideAdapter(String connectTo) {
        def adapter = JavaHttpSubscriptionAdapter.newBuilder()
                .connectTo(connectTo)
                .build()
        adapter.connect().get(TIMEOUT, TimeUnit.SECONDS)
        return adapter
    }

    def "Works with provided RpcCoder"() {
        setup:
        RpcCoder rpcCoder = Spy(new RpcCoder(new ObjectMapper()))
        def adapter = JavaHttpSubscriptionAdapter.newBuilder()
                .rpcCoder(rpcCoder)
                .connectTo("ws://localhost:${port}")
                .build()
        adapter.connect().get(TIMEOUT, TimeUnit.SECONDS)
        when:
        server.onNextReply('{"jsonrpc":"2.0","result":"Hello World!","id":0}')
        def f = adapter.produceRpcFuture(RpcCall.create(String.class, "test_foo"))
        def act = f.get(TIMEOUT, TimeUnit.SECONDS)
        then:
        act == "Hello World!"
        1 * rpcCoder.nextId()
    }

    def "By default connects to 9944"() {
        setup:
        server.stop()
        println("Start new on 9944")
        server = new MockWsServer(9944)
        server.start()
        Thread.sleep(SLEEP)
        def adapter = JavaHttpSubscriptionAdapter.newBuilder()
                .build()
        adapter.connect().get(TIMEOUT, TimeUnit.SECONDS)
        polkadotApi = PolkadotApi.newBuilder().subscriptionAdapter(adapter).rpcCallAdapter(adapter).build()
        when:
        server.onNextReply('{"jsonrpc":"2.0","result":"Hello World!","id":0}')
        def f = polkadotApi.execute(RpcCall.create(String.class, "test_foo"))
        def act = f.get(TIMEOUT, TimeUnit.SECONDS)
        then:
        act == "Hello World!"
    }

    def "Works with provided onClose"(){
        setup:
        def onClose = Spy(Runnable.class)
        def executor = Spy(ExecutorService.class)
        def adapter = JavaHttpSubscriptionAdapter.newBuilder()
                .executor(executor)
                .onClose(onClose)
                .build()
        when:
        adapter.close()
        then:
        1 * onClose.run()
    }

}
