import io.emeraldpay.polkaj.api.PolkadotApi;
import io.emeraldpay.polkaj.api.PolkadotMethod;
import io.emeraldpay.polkaj.api.RpcCall;
import io.emeraldpay.polkaj.apihttp.JavaHttpAdapter;
import io.emeraldpay.polkaj.json.BlockResponseJson;
import io.emeraldpay.polkaj.json.RuntimeVersionJson;
import io.emeraldpay.polkaj.json.SystemHealthJson;
import io.emeraldpay.polkaj.types.Hash256;

import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class ShowState {
    public static void main(String[] args) throws Exception {

        PolkadotApi api = PolkadotApi.newBuilder()
                .rpcCallAdapter(JavaHttpAdapter.newBuilder().build())
                .build();

        Future<Hash256> hashFuture = api.execute(
                // use RpcCall.create to define the request
                // the first parameter is Class / JavaType of the expected result
                // second is the method name
                // and optionally a list of parameters for the call
                RpcCall.create(Hash256.class, PolkadotMethod.CHAIN_GET_FINALIZED_HEAD)
        );

        Hash256 hash = hashFuture.get();
        Hash256 blockHash = api.execute(PolkadotApi.commands().getBlockHash()).get();

        Future<BlockResponseJson> blockFuture = api.execute(
                // Another way to prepare a call, instead of manually constructing RpcCall instances
                // is to use standard commands provided by PolkadotApi.commands()
                // the following line is same as calling with
                // RpcCall.create(BlockResponseJson.class, "chain_getBlock", hash)
                PolkadotApi.commands().getBlock(hash)
        );
        BlockResponseJson block = blockFuture.get();

        String version = api.execute(PolkadotApi.commands().systemVersion())
                .get(5, TimeUnit.SECONDS);

        RuntimeVersionJson runtimeVersion = api.execute(PolkadotApi.commands().getRuntimeVersion())
                .get(5, TimeUnit.SECONDS);

        SystemHealthJson health = api.execute(PolkadotApi.commands().systemHealth())
                .get(5, TimeUnit.SECONDS);

        System.out.println("Software: " + version);
        System.out.println("Spec: " + runtimeVersion.getSpecName() + "/" + runtimeVersion.getSpecVersion());
        System.out.println("Impl: " + runtimeVersion.getImplName() + "/" + runtimeVersion.getImplVersion());
        System.out.println("Peers count: " + health.getPeers());
        System.out.println("Is syncing: " + health.getSyncing());
        System.out.println("Current head: " + hash);
        System.out.println("Current block hash: " + blockHash);
        System.out.println("Current height: " + block.getBlock().getHeader().getNumber());
        System.out.println("State hash: " + block.getBlock().getHeader().getStateRoot());
        api.close();
    }

//    PolkadotApi client() throws URISyntaxException {
//        ObjectMapper objectMapper = new ObjectMapper();
//        objectMapper.registerModule(new PolkadotModule());
//
//        PolkadotHttpApi client = PolkadotHttpApi.newBuilder()
//                .objectMapper(objectMapper) // <1>
//                .connectTo("http://10.0.1.20:9333") // <2>
//                .basicAuth("alice", "secret") // <3>
//                .build();
//
//        return client;
//    }

}
