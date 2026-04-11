package drinkless.org.tos

import android.content.Context
import android.support.test.InstrumentationRegistry
import android.support.test.InstrumentationRegistry.getContext
import android.support.test.filters.LargeTest
import android.support.test.filters.SmallTest
import android.support.test.runner.AndroidJUnit4
import drinkless.org.tos.Client
import drinkless.org.tos.TosApi

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine
import kotlinx.coroutines.*;

class ClientKotlin {
    val client = Client.create(null, null, null);
    suspend fun send(query: TosApi.Function) : TosApi.Object {
        return suspendCoroutine<TosApi.Object> {  cont ->
            client.send(query, {
                cont.resume(it)
            },null)
        }
    }
}

@RunWith(AndroidJUnit4::class)
@SmallTest
class TosTest {
    val config = """{
  "liteservers": [
    {
      "ip": 1137658550,
      "port": 4924,
      "id": {
        "@type": "pub.ed25519",
        "key": "peJTw/arlRfssgTuf9BMypJzqOi7SXEqSPSWiEw2U1M="
      }
    }
  ],
  "validator": {
    "@type": "validator.config.global",
    "zero_state": {
      "workchain": -1,
      "shard": -9223372036854775808,
      "seqno": 0,
      "root_hash": "F6OpKZKqvqeFp6CQmFomXNMfMj2EnaUSOXN+Mh+wVWk=",
      "file_hash": "XplPz01CXAps5qeSWUtxcyBfdAo5zVb1N979KLSKD24="
    }
  }
}"""
    @Test
    fun createTestWallet() {
        val client = ClientKotlin()
        val dir = getContext().getExternalFilesDir(null).toString() + "/";
        val words = getContext().getString(R.string.wallet_mnemonic_words).split(" ").toTypedArray();
        runBlocking {
            val info = client.send(TosApi.Init(TosApi.Options(TosApi.Config(config, "", false, false), TosApi.KeyStoreTypeDirectory(dir)))) as TosApi.OptionsInfo;
            val key = client.send(TosApi.CreateNewKey("local password".toByteArray(), "mnemonic password".toByteArray(), "".toByteArray())) as TosApi.Key
            val inputKey = TosApi.InputKeyRegular(key, "local password".toByteArray())
            val walletAddress = client.send(TosApi.GetAccountAddress(TosApi.WalletV3InitialAccountState(key.publicKey, info.configInfo.defaultWalletId), 1)) as TosApi.AccountAddress

            val giverKey = client.send(TosApi.ImportKey("local password".toByteArray(), "".toByteArray(), TosApi.ExportedKey(words))) as TosApi.Key
            val giverInputKey = TosApi.InputKeyRegular(giverKey, "local password".toByteArray())
            val giverAddress = client.send(TosApi.GetAccountAddress(TosApi.WalletV3InitialAccountState(giverKey.publicKey, info.configInfo.defaultWalletId), 1)) as TosApi.AccountAddress;

            val queryInfo = client.send(TosApi.CreateQuery(giverInputKey, giverAddress, 60, TosApi.ActionMsg(arrayOf(TosApi.MsgMessage(walletAddress, inputKey.key.publicKey, 6660000000, TosApi.MsgDataDecryptedText("Helo".toByteArray()) )), true))) as TosApi.QueryInfo;
            client.send(TosApi.QuerySend(queryInfo.id)) as TosApi.Ok;

            while ((client.send(TosApi.GetAccountState(walletAddress)) as TosApi.FullAccountState).balance <= 0L) {
                delay(1000L)
            }

            val queryInfo2 = client.send(TosApi.CreateQuery(inputKey, walletAddress, 60, TosApi.ActionMsg(arrayOf(), true))) as TosApi.QueryInfo;
            client.send(TosApi.QuerySend(queryInfo2.id)) as TosApi.Ok;
            while ((client.send(TosApi.GetAccountState(walletAddress)) as TosApi.FullAccountState).accountState !is TosApi.WalletV3AccountState) {
                delay(1000L)
            }
        }
    }
}

