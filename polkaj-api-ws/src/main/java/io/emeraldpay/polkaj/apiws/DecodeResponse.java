package io.emeraldpay.polkaj.apiws;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.emeraldpay.polkaj.api.RpcResponse;
import io.emeraldpay.polkaj.api.RpcResponseError;

import java.io.IOException;

/**
 * Decoded JSON response from WebSocket message. The message itself may be a JSON with Subscription event, or standard JSON RPC response.
 * The decoder verifies the content, and depending on it, returns WsResponse with correct type.
 *
 * @see WsResponse
 */
public class DecodeResponse {

    private final TypeMapping<String> subscriptionMapping;
    private final TypeMapping<Integer> rpcMapping;
    private final ObjectMapper objectMapper;

    public DecodeResponse(ObjectMapper objectMapper, TypeMapping<Integer> rpcMapping, TypeMapping<String> subscriptionMapping) {
        this.rpcMapping = rpcMapping;
        this.subscriptionMapping = subscriptionMapping;
        this.objectMapper = objectMapper;
    }

    public WsResponse decode(final String json) throws IOException {
        JsonFactory jsonFactory = objectMapper.getFactory();
        JsonParser parser = jsonFactory.createParser(json);
        if (parser.nextToken() != JsonToken.START_OBJECT) {
            throw new IllegalStateException("Not an object");
        }
        String method = null;
        WsResponse.IdValue<String> value = null;
        Preparsed<Integer> preparsed = new Preparsed<>(objectMapper);
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            if (parser.currentToken() == null) {
                throw new IllegalStateException("JSON finished before data received");
            }
            if (parser.currentToken() != JsonToken.FIELD_NAME) {
                continue;
            }
            String field = parser.currentName();
            if ("jsonrpc".equals(field)) {
                //just skip it
            } else if ("id".equals(field)) {
                preparsed.id = decodeNumber(parser);
                preparsed.type = findType(rpcMapping, preparsed.id);
                if (preparsed.isReady()) {
                    var result = preparsed.build();
                    return WsResponse.rpc(new RpcResponse<>(result.getId(), result.getValue()));
                }
            } else if ("result".equals(field)) {
                parser.nextToken();
                preparsed.node = parser.readValueAsTree();
                if (preparsed.isReady()) {
                    var result = preparsed.build();
                    return WsResponse.rpc(new RpcResponse<>(result.getId(), result.getValue()));
                }
            } else if ("error".equals(field)) {
                //TODO parse error
                preparsed.error = decodeError(parser);
                if (preparsed.id != null) {
                    var result = preparsed.build();
                    return WsResponse.rpc(new RpcResponse<>(result.getId(), result.getValue()));
                }
            } else if ("method".equals(field)) {
                parser.nextToken();
                method = parser.getValueAsString();
                if (value != null) {
                    return WsResponse.subscription(
                            new JavaHttpSubscriptionAdapter.SubscriptionResponse<>(value.getId(), method, value.getValue())
                    );
                }
            } else if ("params".equals(field)) {
                value = decodeSubscription(subscriptionMapping, parser);
                if (method != null) {
                    return WsResponse.subscription(
                            new JavaHttpSubscriptionAdapter.SubscriptionResponse<>(value.getId(), method, value.getValue())
                    );
                }
            }
        }
        throw new IllegalStateException("Either id or result not found in JSON");
    }

    protected RpcResponseError decodeError(JsonParser parser) throws IOException {
        int code = 0;
        String message = null;
        String data = null;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            if (parser.currentToken() == null) {
                break;
            }
            String field = parser.currentName();
            if ("code".equals(field)) {
                code = decodeNumber(parser);
            } else if ("message".equals(field)) {
                message = parser.getValueAsString();
            } else if ("data".equals(field)) {
                data = parser.getValueAsString();
            }
        }
        return new RpcResponseError(code, message, data);

    }

    protected WsResponse.IdValue<String> decodeSubscription(TypeMapping<String> typeMapping, JsonParser parser) throws IOException {
        Preparsed<String> preparsed = new Preparsed<>(objectMapper);
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            if (parser.currentToken() == null) {
                throw new IllegalStateException("JSON finished before data received");
            }

            String field = parser.currentName();
            if ("subscription".equals(field)) {
                preparsed.id = decodeString(parser);
                preparsed.type = findType(typeMapping, preparsed.id);
                if (preparsed.isReady()) {
                    return preparsed.build();
                }
            } else if ("result".equals(field)) {
                parser.nextToken();
                preparsed.node = parser.readValueAsTree();
                if (preparsed.isReady()) {
                    return preparsed.build();
                }
                parser.nextToken();
            }
        }
        throw new IllegalStateException("Either id or result not found in JSON");
    }

    private <T> JavaType findType(TypeMapping<T> typeMapping, T id) {
        JavaType type;
        type = typeMapping.get(id);
        if (type == null) {
            throw new IllegalStateException("Unknown request: " + id);
        }
        return type;
    }

    private Integer decodeNumber(JsonParser parser) throws IOException {
        if (parser.currentToken() != JsonToken.VALUE_NUMBER_INT) {
            parser.nextToken();
        }
        if (!parser.currentToken().isNumeric()) {
            throw new IllegalStateException("Id is not a number");
        }
        return parser.getIntValue();
    }

    private String decodeString(JsonParser parser) throws IOException {
        if (parser.currentToken() != JsonToken.VALUE_STRING) {
            parser.nextToken();
        }
        if (!parser.currentToken().isScalarValue()) {
            throw new IllegalStateException("Id is not a string");
        }
        return parser.getValueAsString();
    }

    public interface TypeMapping<T> {
        JavaType get(T id);
    }

    private static class Preparsed<T> {
        private final ObjectMapper objectMapper;

        T id = null;
        JavaType type = null;
        TreeNode node = null;

        RpcResponseError error;

        public Preparsed(ObjectMapper objectMapper) {
            this.objectMapper = objectMapper;
        }

        public boolean isReady() {
            return id != null &&
                    error != null || (type != null && node != null);
        }

        public WsResponse.IdValue<T> build() throws IOException {
            if (id == null) {
                throw new IllegalStateException("Id is not set");
            }
            if (error != null) {
                return new WsResponse.IdValue<>(id, error);
            }
            if (type == null) {
                throw new IllegalStateException("Type is not set");
            }
            if (node != null) {
                Object value = objectMapper
                        .readerFor(type)
                        .readValue(node.traverse(objectMapper));
                return new WsResponse.IdValue<>(id, value);
            }
            throw new IllegalStateException("Not ready");
        }
    }

}
