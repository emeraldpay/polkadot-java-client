package io.emeraldpay.polkaj.apiws;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.emeraldpay.polkaj.api.*;
import io.emeraldpay.polkaj.json.jackson.PolkadotModule;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * WebSocket based client to Polkadot API. In addition to standard RPC calls it supports subscription to events, i.e.
 * when a call provides multiple responses.
 * <br>
 * Before making calls, a {@link JavaHttpSubscriptionAdapter#connect()} must be called to establish a connection.
 */
public class JavaHttpSubscriptionAdapter implements SubscriptionAdapter, RpcCallAdapter {

    private final AtomicReference<WebSocket> webSocket = new AtomicReference<>(null);
    private final ConcurrentHashMap<Integer, RequestExpectation<?>> execution = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, DefaultSubscription<?>> subscriptions = new ConcurrentHashMap<>();
    private final URI target;
    private final RpcCoder rpcCoder;
    private final DecodeResponse decodeResponse;
    private final HttpClient httpClient;
    private final Runnable onClose;

    private final ScheduledExecutorService control = Executors.newSingleThreadScheduledExecutor();
    private final MessageBuffer messageBuffer = new MessageBuffer();

    private JavaHttpSubscriptionAdapter(URI target, HttpClient httpClient, Runnable onClose, RpcCoder rpcCoder) {
        this.target = target;
        this.httpClient = httpClient;
        this.onClose = onClose;
        var rpcMapping = new DecodeResponse.TypeMapping<Integer>() {
            @Override
            public JavaType get(Integer id) {
                var x = execution.get(id);
                if (x == null) {
                    return null;
                }
                return x.getType();
            }
        };
        var subMapping = new DecodeResponse.TypeMapping<String>() {
            @Override
            public JavaType get(String id) {
                var x = subscriptions.get(id);
                if (x == null) {
                    return null;
                }
                return x.getType();
            }
        };
        this.rpcCoder = rpcCoder;
        this.decodeResponse = new DecodeResponse(rpcCoder.getObjectMapper(), rpcMapping, subMapping);
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    /**
     * Connect to the server. MUST BE CALLED FIRST
     *
     * @return a future for the connection. It always completed with <code>true</code> or and exception if failed to connect
     */
    public CompletableFuture<Boolean> connect() {
        CompletableFuture<Boolean> whenConnected = new CompletableFuture<>();
        WebSocket.Listener listener = newListener(whenConnected);

        CompletableFuture<WebSocket> future = httpClient.newWebSocketBuilder()
                .connectTimeout(Duration.ofSeconds(60))
                .buildAsync(target, listener);

        return future.thenApply(newWebSocket -> this.webSocket.updateAndGet(oldWebSocket -> {
            // in case we somehow connected twice, which in practise is impossible
            if (oldWebSocket != null
                    && oldWebSocket != newWebSocket
                    && !oldWebSocket.isOutputClosed()) {
                oldWebSocket.sendClose(WebSocket.NORMAL_CLOSURE, "reconnect");
            }
            execution.clear();
            subscriptions.clear();
            rpcCoder.resetId();

            // need to send ping, otherwise remote can drop the connection
            control.scheduleAtFixedRate(() -> {
                    byte[] ping = new byte[1];
                    newWebSocket.sendPing(ByteBuffer.wrap(ping));
            }, 30, 45, TimeUnit.SECONDS);

            return newWebSocket;
        })).thenCombine(whenConnected, (webSocket, isOpen) -> isOpen);
    }

    private WebSocket.Listener newListener(final CompletableFuture<Boolean> whenConnected) {
        return new WebSocket.Listener() {
            @Override
            public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                try {
                    if (last) {
                        String message = messageBuffer.last(webSocket, data);
                        WsResponse response = decodeResponse.decode(message);
                        if (response.getType() == WsResponse.Type.SUBSCRIPTION) {
                            accept(response.asEvent());
                        } else {
                            accept(response.asRpc());
                        }
                    } else {
                        messageBuffer.add(webSocket, data);
                    }
                } catch (IllegalStateException e) {
                    // happen when data cannot be properly mapped, i.e. when there is no such subscription or request
                    // we just ignore it
                } catch (Throwable e) {
                    e.printStackTrace();
                }
                webSocket.request(1);
                return null;
            }

            @Override
            public void onOpen(WebSocket webSocket) {
                whenConnected.complete(true);
                webSocket.request(1);
            }

            @Override
            public CompletionStage<?> onPing(WebSocket webSocket, ByteBuffer message) {
                return webSocket.sendPong(message);
            }

        };
    }

    @Override
    public <T> CompletableFuture<T> produceRpcFuture(final RpcCall<T> call) {
        int id = rpcCoder.nextId();
        byte[] payload;
        final ObjectMapper objectMapper = rpcCoder.getObjectMapper();
        try {
            payload = rpcCoder.encode(id, call);
        } catch (JsonProcessingException e) {
            return CompletableFuture.failedFuture(e);
        }
        CompletableFuture<T> whenResponseReceived = new CompletableFuture<>();
        execution.put(id, new RequestExpectation<>(rpcCoder.responseType(
                call.getResultType(objectMapper.getTypeFactory())), whenResponseReceived));
        return webSocket.get()
                .sendText(new String(payload), true)
                .thenCombine(whenResponseReceived, (a, b) -> b);
    }


    @Override
    public <T> CompletableFuture<Subscription<T>> subscribe(final SubscribeCall<T> call) {
        var subscription = new DefaultSubscription<T>(call.getResultType(rpcCoder.getObjectMapper().getTypeFactory()), call.getUnsubscribe(),this);
        var start = this.produceRpcFuture(RpcCall.create(String.class, call.getMethod(), call.getParams()));
        return start.thenApply(id -> {
            subscriptions.put(id, subscription);
            subscription.setId(id);
            return subscription;
        });
    }

    @SuppressWarnings("unchecked")
    public <T> void accept(RpcResponse<T> response) {
        RequestExpectation<T> f = (RequestExpectation<T>) execution.get(response.getId());
        if (f == null) {
            return;
        }
        try {
            if (response.getError() != null) {
                f.getHandler().completeExceptionally(new CompletionException(
                        new RpcException(response.getError().getCode(), response.getError().getMessage(), response.getError().getData())
                ));
            } else {
                f.getHandler().complete(response.getResult());
            }
        } finally {
            execution.remove(response.getId());
        }
    }

    @SuppressWarnings("unchecked")
    public <T> void accept(SubscriptionResponse<T> response) {
        DefaultSubscription<T> s = (DefaultSubscription<T>) subscriptions.get(response.id);
        if (s == null) {
            return;
        }
        s.accept(new Subscription.Event<>(response.method, response.value));
    }

    public boolean removeSubscription(String id) {
        return subscriptions.remove(id) != null;
    }

    @Override
    public void close() {
        webSocket.updateAndGet(old -> {
            if (old != null) {
                old.sendClose(WebSocket.NORMAL_CLOSURE, "close");
            }
            return null;
        });
        execution.clear();
        subscriptions.clear();
        control.shutdownNow();
        if (onClose != null) {
            try {
                onClose.run();
            } catch (Throwable t) {
                System.err.println("Error during onClose call: " + t.getMessage());
            }
        }
    }

    static class SubscriptionResponse<T> {
        private final String id;
        private final String method;
        private final T value;

        public SubscriptionResponse(String id, String method, T value) {
            this.id = id;
            this.method = method;
            this.value = value;
        }

        public String getId() {
            return id;
        }

        public String getMethod() {
            return method;
        }

        public T getValue() {
            return value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof SubscriptionResponse)) return false;
            SubscriptionResponse<?> that = (SubscriptionResponse<?>) o;
            return id.equals(that.id) &&
                    Objects.equals(method, that.method) &&
                    Objects.equals(value, that.value);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, method, value);
        }
    }

    static class RequestExpectation<T> {
        private final JavaType type;
        private final CompletableFuture<T> handler;

        public RequestExpectation(JavaType type, CompletableFuture<T> handler) {
            this.type = type;
            this.handler = handler;
        }

        public JavaType getType() {
            return type;
        }

        public CompletableFuture<T> getHandler() {
            return handler;
        }
    }

    public static class Builder {
        private URI target;
        private ExecutorService executorService;
        private HttpClient httpClient;
        private RpcCoder rpcCoder;
        private Runnable onClose;

        /**
         * Server address URL
         *
         * @param target URL
         * @return builder
         * @throws URISyntaxException if specified url is invalid
         */
        public JavaHttpSubscriptionAdapter.Builder connectTo(String target) throws URISyntaxException {
            return this.connectTo(new URI(target));
        }

        /**
         * Server address URL
         *
         * @param target URL
         * @return builder
         */
        public JavaHttpSubscriptionAdapter.Builder connectTo(URI target) {
            this.httpClient = null;
            this.target = target;
            return this;
        }

        /**
         * Provide a custom HttpClient configured
         *
         * @param httpClient client
         * @return builder
         */
        public JavaHttpSubscriptionAdapter.Builder httpClient(HttpClient httpClient) {
            if (this.executorService != null) {
                throw new IllegalStateException("Custom HttpClient cannot be used with separate Executor");
            }
            this.httpClient = httpClient;
            return this;
        }

        /**
         * Provide a custom ExecutorService to run http calls by default HttpClient
         *
         * @param executorService executor
         * @return builder
         */
        public JavaHttpSubscriptionAdapter.Builder executor(ExecutorService executorService) {
            if (this.httpClient != null) {
                throw new IllegalStateException("Custom HttpClient cannot be used with separate Executor");
            }
            this.executorService = executorService;
            return this;
        }

        /**
         * Provide custom cleanup method.
         *
         * @param onClose to be called on close.
         * @return builder
         */
        public Builder onClose(Runnable onClose){
            this.onClose = onClose;
            return this;
        }

        /**
         * Provide a custom RpcCoder for rpc serialization.
         *
         * @param rpcCoder rpcCoder
         * @return builder
         */
        public JavaHttpSubscriptionAdapter.Builder rpcCoder(RpcCoder rpcCoder){
            this.rpcCoder = rpcCoder;
            return this;
        }


        private void initDefaults() {
            if (rpcCoder == null) {
                final ObjectMapper objectMapper = new ObjectMapper();
                objectMapper.registerModule(new PolkadotModule());
                rpcCoder = new RpcCoder(objectMapper);
            }
            if (httpClient == null && target == null) {
                try {
                    connectTo("ws://127.0.0.1:9944");
                } catch (URISyntaxException e) {
                    //wont happen
                }
            }
            if (executorService == null) {
                ExecutorService executorService = Executors.newCachedThreadPool();
                this.executorService = executorService;
                onClose = executorService::shutdownNow;
            }

            if (this.httpClient == null) {
                httpClient = HttpClient.newBuilder()
                        .version(HttpClient.Version.HTTP_2)
                        .executor(executorService)
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build();
            }
        }

        /**
         * Apply configuration and build client
         *
         * @return new instance of PolkadotRpcClient
         */
        public JavaHttpSubscriptionAdapter build() {
            initDefaults();
            return new JavaHttpSubscriptionAdapter(target, httpClient, onClose, rpcCoder);
        }
    }

}
