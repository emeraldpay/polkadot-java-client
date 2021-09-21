package io.emeraldpay.polkaj.api

import io.emeraldpay.polkaj.api.internal.SubscriptionResponse
import io.emeraldpay.polkaj.api.internal.WsResponse
import spock.lang.Specification

class WsResponseSpec extends Specification {

    def "Creates rpc response"() {
        when:
        def act = WsResponse.rpc(new RpcResponse<Object>(1, "test"))
        then:
        act.getType() == WsResponse.Type.RPC
        act.getValue() == new RpcResponse<Object>(1, "test")
        act.asRpc() == new RpcResponse<Object>(1, "test")
    }

    def "Creates subscription response"() {
        when:
        def act = WsResponse.subscription(new SubscriptionResponse<Object>("EsqruyKPnZvPZ6fr", "test", "test"))
        then:
        act.getType() == WsResponse.Type.SUBSCRIPTION
        act.getValue() == new SubscriptionResponse<Object>("EsqruyKPnZvPZ6fr", "test", "test")
        act.asEvent() == new SubscriptionResponse<Object>("EsqruyKPnZvPZ6fr", "test", "test")
    }

    def "Cannot cast rcp to event"() {
        when:
        WsResponse.rpc(new RpcResponse<Object>(1, "test")).asEvent()
        then:
        thrown(ClassCastException)
    }

    def "Cannot cast event to rpc"() {
        when:
        WsResponse.subscription(new SubscriptionResponse<Object>("EsqruyKPnZvPZ6fr", "test", "test")).asRpc()
        then:
        thrown(ClassCastException)
    }

}
