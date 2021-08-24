package io.emeraldpay.polkaj.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicInteger;

public class RpcCoder {

    private final ObjectMapper objectMapper;
    private final AtomicInteger id = new AtomicInteger(0);

    public RpcCoder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public int nextId() {
        return id.getAndIncrement();
    }

    public void resetId(){
        id.set(0);
    }

    public ObjectMapper getObjectMapper() {
        return objectMapper;
    }

    public JavaType responseType(JavaType resultType) {
        return objectMapper.getTypeFactory().constructType(resultType);
    }

    public JavaType responseType(Class<?> resultClazz) {
        return objectMapper.getTypeFactory().constructType(resultClazz);
    }

    /**
     * Decode JSON RPC response
     *
     * @param id expected id
     * @param content full JSON content
     * @param clazz expected JavaType for the result field
     * @param <T> returning type
     * @return The decoded result
     * @throws CompletionException with RpcException details to let executor know that the response is invalid
     */
    final public <T> T decode(int id, String content, JavaType clazz) {
        JavaType type = objectMapper.getTypeFactory().constructParametricType(RpcResponse.class, clazz);
        RpcResponse<T> response;
        try {
            response = objectMapper.readerFor(type).readValue(content);
        } catch (JsonProcessingException e) {
            throw new CompletionException(
                    new RpcException(-32603, "Server returned invalid JSON", e)
            );
        }
        if (id != response.getId()) {
            throw new CompletionException(
                    new RpcException(-32603, "Server returned invalid id: " + id + " != " + response.getId())
            );
        }
        if (response.getError() != null) {
            throw new CompletionException(
                    new RpcException(response.getError().getCode(), response.getError().getMessage(), response.getError().getData())
            );
        }
        return response.getResult();
    }

    /**
     * Encode RPC request as JSON
     *
     * @param id id of the request
     * @param call the RpcCall to encode
     * @return full JSON of the request
     * @throws JsonProcessingException if cannot encode some of the params into JSON
     */
    final public <T> byte[] encode(int id, RpcCall<T> call) throws JsonProcessingException {
        RpcRequest request = new RpcRequest(id, call.getMethod(), call.getParams());
        return objectMapper.writeValueAsBytes(request);
    }
}
