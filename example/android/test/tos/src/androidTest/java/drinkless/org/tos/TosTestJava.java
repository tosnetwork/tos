package drinkless.org.tos;


import java.util.concurrent.CountDownLatch;

import android.support.test.runner.AndroidJUnit4;
import android.util.Log;
import drinkless.org.tos.Client;
import drinkless.org.tos.TosApi;
import org.junit.Test;
import org.junit.runner.RunWith;

import static android.support.test.InstrumentationRegistry.getContext;

@RunWith(AndroidJUnit4.class)
public class TosTestJava {
    class JavaClient {
        Client client = Client.create(null, null, null);

        public Object send(TosApi.Function query) {
            Object[] result = new Object[1];
            CountDownLatch countDownLatch = new CountDownLatch(1);

            class Callback implements Client.ResultHandler {
                Object[] result;
                CountDownLatch countDownLatch;

                Callback(Object[] result, CountDownLatch countDownLatch) {
                    this.result = result;
                    this.countDownLatch = countDownLatch;
                }

                public void onResult(TosApi.Object object) {
                    if (object instanceof TosApi.Error) {
                        appendLog(((TosApi.Error) object).message);
                    } else {
                        result[0] = object;
                    }
                    if (countDownLatch != null) {
                        countDownLatch.countDown();
                    }
                }
            }

            client.send(query, new Callback(result, countDownLatch) , null);
            if (countDownLatch != null) {
                try {
                    countDownLatch.await();
                } catch (Throwable e) {
                    appendLog(e.toString());
                }
            }
            return result[0];
        }
    }
    String config = "{\n"+
        "  \"liteservers\": [\n"+
        "    {\n"+
        "      \"ip\": 1137658550,\n"+
        "      \"port\": 4924,\n"+
        "      \"id\": {\n"+
        "        \"@type\": \"pub.ed25519\",\n"+
        "        \"key\": \"peJTw/arlRfssgTuf9BMypJzqOi7SXEqSPSWiEw2U1M=\"\n"+
        "      }\n"+
        "    }\n"+
        "  ],\n"+
        "  \"validator\": {\n"+
        "    \"@type\": \"validator.config.global\",\n"+
        "    \"zero_state\": {\n"+
        "      \"workchain\": -1,\n"+
        "      \"shard\": -9223372036854775808,\n"+
        "      \"seqno\": 0,\n"+
        "      \"root_hash\": \"F6OpKZKqvqeFp6CQmFomXNMfMj2EnaUSOXN+Mh+wVWk=\",\n"+
        "      \"file_hash\": \"XplPz01CXAps5qeSWUtxcyBfdAo5zVb1N979KLSKD24=\"\n"+
        "    }\n"+
        "  }\n"+
        "}";

    private void appendLog(String log) {
        Log.w("XX", log);
    }

    @Test
    public void createTestWallet() {
        appendLog("start...");
        String dir =  getContext().getExternalFilesDir(null) + "/";
        String[] words = getContext().getString(R.string.wallet_mnemonic_words).split(" ");
        JavaClient client = new JavaClient();
        Object result = client.send(new TosApi.Init(new TosApi.Options(new TosApi.Config(config, "", false, false), new TosApi.KeyStoreTypeDirectory((dir)))));
        if (!(result instanceof TosApi.OptionsInfo)) {
            appendLog("failed to set config");
            return;
        }
        appendLog("config set ok");
        TosApi.OptionsInfo info = (TosApi.OptionsInfo)result;
        TosApi.Key key = (TosApi.Key) client.send(new TosApi.CreateNewKey("local password".getBytes(), "mnemonic password".getBytes(), "".getBytes()));
        TosApi.InputKey inputKey = new TosApi.InputKeyRegular(key, "local password".getBytes());
        TosApi.AccountAddress walletAddress = (TosApi.AccountAddress)client.send(new TosApi.GetAccountAddress(new TosApi.WalletV3InitialAccountState(key.publicKey, info.configInfo.defaultWalletId), 1));

        TosApi.Key giverKey = (TosApi.Key)client.send(new TosApi.ImportKey("local password".getBytes(), "".getBytes(), new TosApi.ExportedKey(words))) ;
        TosApi.InputKey giverInputKey = new TosApi.InputKeyRegular(giverKey, "local password".getBytes());
        TosApi.AccountAddress giverAddress = (TosApi.AccountAddress)client.send(new TosApi.GetAccountAddress(new TosApi.WalletV3InitialAccountState(giverKey.publicKey, info.configInfo.defaultWalletId), 1));

        appendLog("sending grams...");
        TosApi.QueryInfo queryInfo = (TosApi.QueryInfo)client.send(new TosApi.CreateQuery(giverInputKey, giverAddress, 60, new TosApi.ActionMsg(new TosApi.MsgMessage[]{new TosApi.MsgMessage(walletAddress, "", 6660000000L, new TosApi.MsgDataText("Hello".getBytes()) )}, true)));
        result = client.send(new TosApi.QuerySend(queryInfo.id));
        if (!(result instanceof TosApi.Ok)) {
            appendLog("failed to send grams");
            return;
        }
        appendLog("grams sent, getting balance");

        while (true) {
            TosApi.FullAccountState state = (TosApi.FullAccountState) client.send(new TosApi.GetAccountState(walletAddress));
            if (state.balance <= 0L) {
                try {
                    Thread.sleep(1000);
                } catch (Throwable e) {
                    appendLog(e.toString());
                }
            } else {
                appendLog(String.format("balance = %d", state.balance));
                break;
            }
        }
    }
}
