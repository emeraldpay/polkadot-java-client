package io.emeraldpay.polkaj.apihttp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.emeraldpay.polkaj.api.*;
import io.emeraldpay.polkaj.json.jackson.PolkadotModule;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Default JSON RPC HTTP client for Polkadot API. It uses Java 11 HttpClient implementation for requests.
 * Each request made from that client has a uniq id, from a monotone sequence starting on 0. A new instance is
 * supposed to be create through {@link JavaHttpAdapter#newBuilder()}:
 * <br>
 * The class is AutoCloseable, with {@link JavaHttpAdapter#close()} methods, which shutdown a thread (or threads) used for http requests.
 *
 * <br>
 * Example:
 * <pre><code>
 * PolkadotHttpApi client = PolkadotHttpApi.newBuilder().build();
 * Future&lt;Hash256&gt; hash = client.execute(Hash256.class, "chain_getFinalisedHead");
 * System.out.println("Current head: " + hash.get());
 * </code></pre>
 */
public class JavaHttpAdapter implements RpcCallAdapter {

    private static final String APPLICATION_JSON = "application/json";

    private final HttpClient httpClient;
    private final HttpRequest.Builder request;
    private final Runnable onClose;
    private final RpcCoder rpcCoder;

    private boolean closed = false;

    private JavaHttpAdapter(URI target, HttpClient httpClient, String basicAuth, Duration timeout, Runnable onClose, RpcCoder rpcCoder) {
        this.httpClient = httpClient;

        HttpRequest.Builder request = HttpRequest.newBuilder()
                .uri(target)
                .timeout(timeout)
                .header("User-Agent", "Polkaj/0.3") //TODO generate version during compilation
                .header("Content-Type", APPLICATION_JSON);

        if (basicAuth != null) {
            request = request.header("Authorization", basicAuth);
        }

        this.request = request;
        this.onClose = onClose;
        this.rpcCoder = rpcCoder;
    }

    /**
     * Execute JSON RPC request
     *
     * @param call RPC call to execute
     * @param <T> type of the result
     * @return CompletableFuture for the result. Note that the Future may throw RpcException when it get
     * @see RpcException
     */
    @Override
    public <T> CompletableFuture<T> produceRpcFuture(RpcCall<T> call) {
        if (closed) {
            return CompletableFuture.failedFuture(
                    new IllegalStateException("Client is already closed")
            );
        }
        final ObjectMapper objectMapper = rpcCoder.getObjectMapper();
        int id = rpcCoder.nextId();
        JavaType type = call.getResultType(objectMapper.getTypeFactory());
        try {
            HttpRequest.Builder request = this.request.copy()
                    .POST(HttpRequest.BodyPublishers.ofByteArray(rpcCoder.encode(id, call)));
            return httpClient.sendAsync(request.build(), HttpResponse.BodyHandlers.ofString())
                    .thenApply(this::verify)
                    .thenApply(HttpResponse::body)
                    .thenApply(content -> rpcCoder.decode(id, content, type));
        } catch (JsonProcessingException e) {
            return CompletableFuture.failedFuture(
                    new RpcException(-32600, "Unable to encode request as JSON: " + e.getMessage(), e)
            );
        } catch (CompletionException e){
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Verify the HTTP response meta, i.e. statuc code, headers, etc.
     *
     * @param response HTTP response from server
     * @return The response itself if all is ok
     * @throws CompletionException with RpcException details to let executor know that the response is invalid
     * @see CompletionException
     * @see RpcException
     */
    public HttpResponse<String> verify(HttpResponse<String> response) {
        if (response.statusCode() != 200) {
            throw new CompletionException(
                    new RpcException(-32000, "Server returned error status: " + response.statusCode())
            );
        }
        //response shouldn't contain non-ascii so charset can be ignored
        if (!response.headers().firstValue("content-type").orElse(APPLICATION_JSON).startsWith(APPLICATION_JSON)) {
            throw new CompletionException(
                    new RpcException(-32000, "Server returned invalid content-type: " + response.headers().firstValue("content-type"))
            );
        }
        return response;
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        if (onClose != null) {
            try {
                onClose.run();
            } catch (Throwable t) {
                System.err.println("Error during onClose call: " + t.getMessage());
            }
        }
    }

    /**
     * PolkadotRpcClient builder. All of the configurations are optional, and the default build would use
     * a standard Java HttpClient without any authorization connecting to localhost:9933 and using
     * a new instance of a Jackson ObjectMapper with PolkadotModule enabled.
     *
     * @see JavaHttpAdapter
     * @see HttpClient
     * @see PolkadotModule
     */
    public static class Builder {
        private URI target;
        private ExecutorService executorService;
        private String basicAuth;
        private HttpClient httpClient;
        private RpcCoder rpcCoder;
        private Runnable onClose;
        private Duration timeout;

        /**
         * Setup Basic Auth for RPC calls
         *
         * @param username username
         * @param password password
         * @return builder
         */
        public Builder basicAuth(String username, String password) {
            this.basicAuth = "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
            return this;
        }

        /**
         * Server address URL
         *
         * @param target URL
         * @return builder
         * @throws URISyntaxException if specified url is invalid
         */
        public Builder connectTo(String target) throws URISyntaxException {
            return this.connectTo(new URI(target));
        }

        /**
         * Server address URL
         *
         * @param target URL
         * @return builder
         */
        public Builder connectTo(URI target) {
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
        public Builder httpClient(HttpClient httpClient) {
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
        public Builder executor(ExecutorService executorService) {
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
         * Override the default timeout with a custom duration.
         *
         * @param timeout Duration
         * @return builder
         */
        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        /**
         * Provide a custom RpcCoder for rpc serialization.
         *
         * @param rpcCoder rpcCoder
         * @return builder
         */
        public JavaHttpAdapter.Builder rpcCoder(RpcCoder rpcCoder){
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
                    connectTo("http://127.0.0.1:9933");
                } catch (URISyntaxException e) { }
            }

            if (executorService == null) {
                ExecutorService executorService = Executors.newCachedThreadPool();
                this.executorService = executorService;
                onClose = executorService::shutdown;
            }

            if (timeout == null) {
                timeout = Duration.ofMinutes(1);
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
        public JavaHttpAdapter build() {
            initDefaults();
            return new JavaHttpAdapter(target, httpClient, basicAuth, timeout, onClose, rpcCoder);
        }

    }
}
