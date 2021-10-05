import io.emeraldpay.polkaj.api.PolkadotApi;
import io.emeraldpay.polkaj.api.Subscription;
import io.emeraldpay.polkaj.api.SubscriptionAdapter;
import io.emeraldpay.polkaj.apiokhttp.OkHttpSubscriptionAdapter;
import io.emeraldpay.polkaj.apiws.JavaHttpSubscriptionAdapter;
import io.emeraldpay.polkaj.json.BlockJson;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class FollowState {

    public static void main(String[] args) throws InterruptedException, ExecutionException, TimeoutException {
        final boolean useOkhttp = Arrays.asList(args).contains("okhttp");
        final SubscriptionAdapter wsAdapter = useOkhttp ?
                OkHttpSubscriptionAdapter.newBuilder().connectTo("ws://192.168.68.93:9944").build() :
                JavaHttpSubscriptionAdapter.newBuilder().build();

        PolkadotApi api = PolkadotApi.newBuilder()
                .subscriptionAdapter(wsAdapter)
                .build();

        // IMPORTANT! connect to the node as the first step before making calls or subscriptions.
        // OkHttpSubscriptionAdapter handles this for you
        if(wsAdapter instanceof  JavaHttpSubscriptionAdapter)
            ((JavaHttpSubscriptionAdapter)wsAdapter).connect().get(5, TimeUnit.SECONDS);

        Future<Subscription<BlockJson.Header>> hashFuture = api.subscribe(SubscriptionAdapter.subscriptions().newHeads());

        Subscription<BlockJson.Header> subscription = hashFuture.get(5, TimeUnit.SECONDS);
        subscription.handler((Subscription.Event<BlockJson.Header> event) -> {
            BlockJson.Header header = event.getResult();
            List<String> line = List.of(
                    Instant.now().truncatedTo(ChronoUnit.SECONDS).toString(),
                    header.getNumber().toString(),
                    header.getStateRoot().toString()
            );
            System.out.println(String.join("\t", line));
        });

    }
}
