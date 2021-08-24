import io.emeraldpay.polkaj.api.PolkadotApi;
import io.emeraldpay.polkaj.api.StandardCommands;
import io.emeraldpay.polkaj.apihttp.JavaHttpAdapter;
import io.emeraldpay.polkaj.scale.ScaleExtract;
import io.emeraldpay.polkaj.scaletypes.Metadata;
import io.emeraldpay.polkaj.scaletypes.MetadataReader;

import java.util.concurrent.Future;

/**
 * Run with: gradle run -PmainClass=DescribeRuntime
 */
public class DescribeRuntime {

    public static void main(String[] args) throws Exception {
        PolkadotApi api = PolkadotApi.newBuilder()
                .rpcCallAdapter(JavaHttpAdapter.newBuilder().build())
                .build();
        Future<Metadata> metadataFuture = api.execute(StandardCommands.getInstance().stateMetadata())
                .thenApply(ScaleExtract.fromBytesData(new MetadataReader()));

        System.out.println("Runtime Metadata:");
        Metadata metadata = metadataFuture.get();
        metadata.getModules().forEach((module) -> {
            System.out.println("  module: " + module.getName() + " (storage: " +
                    (module.getStorage() != null ? module.getStorage().getPrefix() : "NONE")
                    + ")"
            );
            if (module.getStorage() != null && module.getStorage().getEntries() != null) {
                module.getStorage().getEntries().forEach((entry) -> {
                    System.out.println("     " + entry.getName());
                    entry.getDocumentation().stream()
                            .filter(s1 -> !s1.isEmpty())
                            .map(String::trim)
                            .forEach(s ->
                                    System.out.println("     : " + s)
                            );
                });
            }
        });
        api.close();
    }
}
