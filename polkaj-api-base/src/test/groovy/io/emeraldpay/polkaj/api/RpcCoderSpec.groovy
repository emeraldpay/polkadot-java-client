package io.emeraldpay.polkaj.api

import com.fasterxml.jackson.databind.ObjectMapper
import io.emeraldpay.polkaj.types.Hash256
import io.emeraldpay.polkaj.json.BlockResponseJson
import io.emeraldpay.polkaj.json.jackson.PolkadotModule
import spock.lang.Specification

import java.util.concurrent.CompletionException

class RpcCoderSpec extends Specification {

    RpcCoder rpcCoder = new RpcCoder(new ObjectMapper().tap { registerModule(new PolkadotModule())})

    def "Encode empty params request"() {
        when:
        def act = rpcCoder.encode(1, RpcCall.create(Void.class, "test_foo"))
        then:
        new String(act) == '{"jsonrpc":"2.0","id":1,"method":"test_foo","params":[]}'
    }

    def "Encode single param request"() {
        when:
        def act = rpcCoder.encode(1, RpcCall.create(Void.class, "test_foo", "hello"))
        then:
        new String(act) == '{"jsonrpc":"2.0","id":1,"method":"test_foo","params":["hello"]}'
    }

    def "Encode multi params request"() {
        when:
        def act = rpcCoder.encode(2, RpcCall.create(Void.class,"test_foo", Hash256.from("0x5d83f66b61701da4cbd7a60137db89c69469a4f798b62aba9176ab253b423828"), 100, false))
        then:
        new String(act) == '{"jsonrpc":"2.0","id":2,"method":"test_foo","params":["0x5d83f66b61701da4cbd7a60137db89c69469a4f798b62aba9176ab253b423828",100,false]}'
    }

    def "Encode object params request"() {
        when:
        def act = rpcCoder.encode(3, RpcCall.create(Void.class,"test_foo", [foo: "bar", baz: 1]))
        then:
        new String(act) == '{"jsonrpc":"2.0","id":3,"method":"test_foo","params":[{"foo":"bar","baz":1}]}'
    }

    def "Decode basic"() {
        setup:
        def response = '{\n' +
                '  "jsonrpc": "2.0",\n' +
                '  "result": "0x5d83f66b61701da4cbd7a60137db89c69469a4f798b62aba9176ab253b423828",\n' +
                '  "id": 0\n' +
                '}'
        when:
        def act = rpcCoder.decode(0, response, rpcCoder.responseType(String))
        then:
        act == '0x5d83f66b61701da4cbd7a60137db89c69469a4f798b62aba9176ab253b423828'
    }

    def "Decode null"() {
        setup:
        def response = '{\n' +
                '  "jsonrpc": "2.0",\n' +
                '  "result": null,\n' +
                '  "id": 0\n' +
                '}'
        when:
        def act = rpcCoder.decode(0, response, rpcCoder.responseType(BlockResponseJson))
        then:
        act == null
    }

    def "Decode Hash256"() {
        setup:
        def response = '{\n' +
                '  "jsonrpc": "2.0",\n' +
                '  "result": "0x5d83f66b61701da4cbd7a60137db89c69469a4f798b62aba9176ab253b423828",\n' +
                '  "id": 0\n' +
                '}'
        when:
        def act = rpcCoder.decode(0, response, rpcCoder.responseType(Hash256))
        then:
        act == Hash256.from('0x5d83f66b61701da4cbd7a60137db89c69469a4f798b62aba9176ab253b423828')
    }

    def "Decode error"() {
        setup:
        def response = '{\n' +
                '  "jsonrpc": "2.0",\n' +
                '  "error": {"code": 100, "message": "Test error", "data": "Test data"},\n' +
                '  "id": 0\n' +
                '}'
        when:
        rpcCoder.decode(0, response, rpcCoder.responseType(BlockResponseJson))
        then:
        def t = thrown(CompletionException)
        t.cause instanceof RpcException
        t.message == "io.emeraldpay.polkaj.api.RpcException: RPC Exception 100: Test error (Test data)"
        with((RpcException)t.cause) {
            code == 100
            rpcMessage == "Test error"
            rpcData == "Test data"
        }
    }

    def "Fail to decode if wrong id"() {
        setup:
        def response = '{\n' +
                '  "jsonrpc": "2.0",\n' +
                '  "result": "0x5d83f66b61701da4cbd7a60137db89c69469a4f798b62aba9176ab253b423828",\n' +
                '  "id": 0\n' +
                '}'
        when:
        rpcCoder.decode(1, response, rpcCoder.responseType(String))
        then:
        def t = thrown(CompletionException)
        t.cause instanceof RpcException
        t.message == "io.emeraldpay.polkaj.api.RpcException: RPC Exception -32603: Server returned invalid id: 1 != 0"
        with((RpcException)t.cause) {
            code == -32603
            rpcMessage == "Server returned invalid id: 1 != 0"
            rpcData == null
        }
    }

    def "Fail to decode if invalid json"() {
        setup:
        def response = '{\n  "jsonrpc": "2'
        when:
        rpcCoder.decode(1, response, rpcCoder.responseType(String))
        then:
        def t = thrown(CompletionException)
        t.cause instanceof RpcException
        t.message == "io.emeraldpay.polkaj.api.RpcException: RPC Exception -32603: Server returned invalid JSON"
        with((RpcException)t.cause) {
            code == -32603
            rpcMessage == "Server returned invalid JSON"
            rpcData == null
        }
    }

}
