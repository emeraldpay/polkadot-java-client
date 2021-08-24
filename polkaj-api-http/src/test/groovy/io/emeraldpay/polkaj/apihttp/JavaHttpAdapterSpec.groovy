package io.emeraldpay.polkaj.apihttp

import com.fasterxml.jackson.databind.ObjectMapper
import io.emeraldpay.polkaj.api.RpcCall
import io.emeraldpay.polkaj.api.RpcCallAdapter
import io.emeraldpay.polkaj.api.RpcCoder
import io.emeraldpay.polkaj.api.RpcAdapterSpec
import io.emeraldpay.polkaj.json.jackson.PolkadotModule

import java.time.Duration
import java.util.concurrent.ExecutorService

class JavaHttpAdapterSpec extends RpcAdapterSpec {

    @Override
    RpcCallAdapter provideAdapter(String connectTo, String username, String password, Duration timeout) {
        return JavaHttpAdapter.newBuilder()
                .connectTo("http://localhost:18080")
                .basicAuth(username, password)
                .timeout(timeout)
                .build()
    }

    def "Uses provided onClose"(){
        setup:
        def onClose = Spy(Runnable.class)
        def executor = Spy(ExecutorService.class)
        def adapter = JavaHttpAdapter.newBuilder()
            .executor(executor)
            .onClose(onClose)
            .build()
        when:
        adapter.close()
        then:
        1 * onClose.run()
    }

    def "Uses provided RpcCoder"(){
        setup:
        def objectMapper = new ObjectMapper().tap {
            registerModule(new PolkadotModule())
        }
        def rpcCoder = Spy(new RpcCoder(objectMapper))
        def adapter = JavaHttpAdapter.newBuilder()
            .rpcCoder(rpcCoder)
            .build()
        when:
        adapter.produceRpcFuture(RpcCall.create(String.class, "test"))
        then:
        1 * rpcCoder.nextId()
    }

}
