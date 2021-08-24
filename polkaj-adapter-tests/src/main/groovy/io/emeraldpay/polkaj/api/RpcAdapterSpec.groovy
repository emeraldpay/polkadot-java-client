package io.emeraldpay.polkaj.api

import io.emeraldpay.polkaj.json.BlockResponseJson
import io.emeraldpay.polkaj.types.Hash256
import org.mockserver.integration.ClientAndServer
import org.mockserver.model.Delay
import org.mockserver.model.HttpRequest
import org.mockserver.model.HttpResponse
import org.mockserver.model.MediaType
import spock.lang.Shared
import spock.lang.Specification

import java.net.http.HttpTimeoutException
import java.nio.charset.Charset
import java.time.Duration
import java.util.concurrent.ExecutionException


abstract class RpcAdapterSpec extends Specification{


    PolkadotApi polkadotApi

    @Shared
    ClientAndServer mockServer

    def setup() {
        mockServer = ClientAndServer.startClientAndServer(18080)
        def adapter = provideAdapter("http://localhost:18080",
                "testuser",
                "testpassword",
                Duration.ofSeconds(1)
        )
        polkadotApi = PolkadotApi.newBuilder()
                .rpcCallAdapter(adapter)
                .build()
    }

    def cleanup() {
        mockServer.stop()
    }

    abstract RpcCallAdapter provideAdapter(String connectTo, String username, String password, Duration timeout)

    def "Make request"() {
        setup:
        def response = '{\n' +
                '  "jsonrpc": "2.0",\n' +
                '  "result": "0x5d83f66b61701da4cbd7a60137db89c69469a4f798b62aba9176ab253b423828",\n' +
                '  "id": 0\n' +
                '}'

//        TODO can the following couple of lines be pulled into a helper method and re-used?
        mockServer.when(
                HttpRequest.request()
        ).respond(
                HttpResponse.response(response).withContentType(MediaType.APPLICATION_JSON)
        )
        when:
        def act = polkadotApi.execute(RpcCall.create(String, "chain_getFinalisedHead"))
        then:
        act.get() == "0x5d83f66b61701da4cbd7a60137db89c69469a4f798b62aba9176ab253b423828"

    }

    def "Doesn't make requests after close"() {
        setup:
        def response = '{\n' +
                '  "jsonrpc": "2.0",\n' +
                '  "result": "0x5d83f66b61701da4cbd7a60137db89c69469a4f798b62aba9176ab253b423828",\n' +
                '  "id": 0\n' +
                '}'
        mockServer.when(
                HttpRequest.request()
        ).respond(
                HttpResponse.response(response).withContentType(MediaType.APPLICATION_JSON)
        )
        when:
        def act = polkadotApi.execute(RpcCall.create(String, "chain_getFinalisedHead"))
        then:
        act.get() != null

        when:
        polkadotApi.close()
        polkadotApi.execute(RpcCall.create(String, "chain_getFinalisedHead")).get()

        then:
        def t = thrown(ExecutionException)
        t.cause instanceof IllegalStateException

    }

    def "Timeouts in one second"() {
        setup:
        def response = '{\n' +
                '  "jsonrpc": "2.0",\n' +
                '  "result": "0x5d83f66b61701da4cbd7a60137db89c69469a4f798b62aba9176ab253b423828",\n' +
                '  "id": 0\n' +
                '}'
        mockServer.when(
                HttpRequest.request()
        ).respond(
                HttpResponse.response(response).withContentType(MediaType.APPLICATION_JSON).withDelay(Delay.seconds(2))
        )

        when:
        polkadotApi.execute(RpcCall.create(String, "chain_getFinalisedHead")).get()

        then:
        def t = thrown(ExecutionException)
        t.cause instanceof HttpTimeoutException

    }

    def "Make request for complex object"() {
        setup:
        def response = '{' +
                '  "jsonrpc": "2.0",' +
                '  "result": {' +
                '    "block": {' +
                '      "extrinsics": [],' +
                '      "header": {' +
                '        "digest": {' +
                '          "logs": []' +
                '        },' +
                '        "extrinsicsRoot": "0xeaa154a7541c9ed34218b89c1f5e4add2976329ba830543a72d8115c61725212",' +
                '        "number": "0x401a1",' +
                '        "parentHash": "0xb5ba465c2e20fd844d9f0a8ee34680ced6121544af22cffa8236af9ca00d13b1",' +
                '        "stateRoot": "0x0984f5c13d7d271467332697fa5fc191539c1441f5ca1b234618ff25638b7d66"' +
                '      }' +
                '    },' +
                '    "justifications": []' +
                '  },' +
                '  "id": 0' +
                '}'
        mockServer.when(
                HttpRequest.request()
        ).respond(
                HttpResponse.response(response).withContentType(MediaType.APPLICATION_JSON.withCharset(Charset.forName("UTF-8")))
        )
        when:
        def act = polkadotApi.execute(RpcCall.create(BlockResponseJson, "chain_getBlock", Hash256.from("0x9130103f8fbca52a79042211383946b39e6269b6ab49bc08035c9893d782c1bb"))).get()
        then:
        mockServer.verify(
                HttpRequest.request()
                        .withBody('{"jsonrpc":"2.0","id":0,"method":"chain_getBlock","params":["0x9130103f8fbca52a79042211383946b39e6269b6ab49bc08035c9893d782c1bb"]}')
        )

        act.justifications.length == 0
        act.block != null
        with(act.block) {
            header.number == 0x401a1
            header.extrinsicsRoot == Hash256.from("0xeaa154a7541c9ed34218b89c1f5e4add2976329ba830543a72d8115c61725212")
        }

    }

    def "Fail if non-200 status"() {
        setup:
        mockServer.when(
                HttpRequest.request()
        ).respond(
                HttpResponse.response("").withContentType(MediaType.APPLICATION_JSON).withStatusCode(503)
        )
        when:
        polkadotApi.execute(RpcCall.create(String, "chain_getFinalisedHead")).get()
        then:
        def t = thrown(ExecutionException)
        t.cause instanceof RpcException
        with((RpcException)t.cause) {
            code == -32000
            rpcMessage.contains("503")
        }

    }

    def "Fail if non-JSON content"() {
        setup:
        mockServer.when(
                HttpRequest.request()
        ).respond(
                HttpResponse.response("").withContentType(MediaType.TEXT_PLAIN)
        )
        when:
        polkadotApi.execute(RpcCall.create(String, "chain_getFinalisedHead")).get()
        then:
        def t = thrown(ExecutionException)
        t.cause instanceof RpcException
        t.cause.code == -32000

    }

    def "Process response error"() {
        setup:
        def response = '{' +
                '  "jsonrpc": "2.0",' +
                '  "error": {"code": -32601, "message": "Method not found"},' +
                '  "id": 0' +
                '}'
        mockServer.when(
                HttpRequest.request()
        ).respond(
                HttpResponse.response(response).withContentType(MediaType.APPLICATION_JSON)
        )
        when:
        polkadotApi.execute(RpcCall.create(String, "chain_getFinalisedHead")).get()
        then:
        def t = thrown(ExecutionException)
        t.cause instanceof RpcException
        with((RpcException)t.cause) {
            code == -32601
            rpcMessage == "Method not found"
        }

    }

    def "Send basic auth"() {
        setup:

        def response = '{' +
                '  "jsonrpc": "2.0",' +
                '  "result": "0x5d83f66b61701da4cbd7a60137db89c69469a4f798b62aba9176ab253b423828",' +
                '  "id": 0' +
                '}'
        mockServer.when(
                HttpRequest.request()
        ).respond(
                HttpResponse.response(response).withContentType(MediaType.APPLICATION_JSON)
        )
        when:
        def act = polkadotApi.execute(RpcCall.create(String, "chain_getFinalisedHead")).get()
        then:
        act == "0x5d83f66b61701da4cbd7a60137db89c69469a4f798b62aba9176ab253b423828"
        mockServer.verify(
                HttpRequest.request().withHeader("Authorization", "Basic dGVzdHVzZXI6dGVzdHBhc3N3b3Jk")
        )

    }

}