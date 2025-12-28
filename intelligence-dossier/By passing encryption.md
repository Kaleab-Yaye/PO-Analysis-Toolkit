

# TL;DR:

In this write-up, I fully present how I was able to intercept, read, and analyze the encrypted data exchange between the client (app) and the server (API). So, here is a small conclusion of how I did it.

I started by trying to find fingerprints of the commonly used Java-layer encryption libs in the app. I built a list, and based on that list, I found around 15 positive hits. My plan was to go and see how the app uses each of those 15 libs, so I started with `javax.crypto`. To see if the devs had used their own custom encryption built upon `java.crypto`, I hooked `SecretKeySpec()` using `Frida` and analyzed the result. The result was that all the usage of this package was by other integrated SDKs and not by the core of the app. This made me realize that this could be the case with the majority of the libraries that I had found. I changed my strategy and started analyzing the `GET` and `POST` packets sent from the app, and then a pattern emerged: `_sign`. This string was baked into every query request. So, I performed a text search on the decompiled source code of the app to locate where the string is being concatenated with the rest of the query. That search led me to the `EncryptionHelper` class. This class has very interesting public methods, named `encodeParams` and `decodeApi`. By hooking what goes in and out of those two methods with a script that logs Thread ID and time, I was able to cross-check the requests with `Burp Suite` and verify I am indeed reading the raw unencrypted and decrypted data.

# Full Story

## Identifying The Encryption Environment of the App

So, this time, instead of doing static analysis to find where encryptions happen (which might involve writing scripts to search text for each potential Encryption Java/Native Library), I decided to go with dynamic analysis first to see if the app uses well-known encryption libraries.

Android apps have two ways to enforce encryption: they can either use Java-layer encryption or native-level encryption. Also, if the encryption is happening at the native layer, they could either use their own encryption engine written in C or C++ or integrate a third-party native layer encryption library. //Those are the possibilities that we have to keep in mind.

## The Java Layer

The Java encryption layer involves two things: literal `JVM` encryption libraries (could be custom or integrated) or Java classes that are used as a bridge to native encryption that the app might be undergoing. So, I started looking up the most common encryption-related classes and encryption libraries that are used in many Android apps.

### Building the List

After days of looking for these encryption libraries in the official Android Documentation, Java Cryptography Architecture (`JCA`), and widely-used third-party libraries, I ended up with the following list.
NOTE: The list is not a complete list of every encryption library but of the most common ones, and I will edit this list from time to time.

```java
// standard Java Enc
      'javax.crypto.Cipher',
      'javax.crypto.spec.SecretKeySpec',
      'java.security.KeyStore',
      'java.security.Security',

      // Shared pref Enc
      'androidx.security.crypto.EncryptedSharedPreferences',
      'androidx.security.crypto.EncryptedFile',
      'androidx.security.crypto.MasterKeys',

      // Google ENC
      'com.google.crypto.tink.KeysetHandle',
      'com.google.crypto.tink.Aead',
      'com.google.crypto.tink.aead.AeadConfig',

      // Bouncy Castle (Not common, but good for checking)
      'org.bouncycastle.jce.provider.BouncyCastleProvider',
      'org.bouncycastle.crypto.engines.AESEngine',
      'org.spongycastle.jce.provider.BouncyCastleProvider',
      'org.spongycastle.crypto.engines.AESEngine',

      // SQLCipher Java Lib
      'net.sqlcipher.database.SQLiteDatabase',
      'net.sqlcipher.database.SQLiteOpenHelper',

      // Facebook Enc
      'com.facebook.crypto.Crypto',
      'com.facebook.crypto.keychain.KeyChain',

      // OpenSSL
      'org.conscrypt.Conscrypt',
      'org.conscrypt.OpenSSLProvider',

      // Libsodium Enc Lib (very common and mostly found native layer Enc Lib)
      'org.libsodium.jni.Sodium',
      'com.goterl.lazysodium.LazySodium',
      'com.goterl.lazysodium.LazySodiumJNI',

      // OpenSSL Java wrappers
      'org.apache.harmony.xnet.provider.jsse.OpenSSLProvider',

      // other common Enc Libs
      'okio.ByteString',                 // handles Bytes and is used by many 3rd party Enc
      //'com.squareup.okhttp3.OkHttpClient', // TLS pinning, Uncomment if not already done
      'com.google.android.gms.security.ProviderInstaller', // another security(Enc) provider from google

      // show a physical store of a key
      'android.security.keystore.KeyProperties',
      'android.security.keystore.KeyGenParameterSpec',

      // Tink helper classes
      'com.google.crypto.tink.integration.android.AndroidKeysetManager',

      // less common crypto wrappers
      'com.tozny.crypto.android.AesCbcWithIntegrity', // example third-party wrapper
      'com.scottyab.aescrypt.AESCrypt' // common simple AES wrapper lib
```

### Using The List

So, as I have said, we are not going to do a static keyword search on the app's source code, as it will take an unreasonably huge amount of time to verify each of those. So, I decided to do Dynamic Analysis instead and ask the `Java Class Loader` (`classPathLoader`/`dexPathLoader`) to check if traces of those libraries are present.

This is the `Frida` hook that I wrote and used for that purpose:

```javascript
// detect_crypto_libs.js
// Frida script — detects presence of common Java crypto libraries and related APIs.
// No hooking; only class-existence checks and safe invocations. Defensively coded.

if (Java.available) {
  Java.perform(function () {
    var detections = [];
    var notFound = [];

    function safeCheckClass(name) {
      try {
        // Attempt to use the class; Java.use throws if missing.
        Java.use(name);
        console.log('[+] FOUND: ' + name);
        detections.push(name);
        return true;
      } catch (err) {
        // not found
        // Keep output concise but informative
        console.log('[-] not found: ' + name);
        notFound.push(name);
        return false;
      }
    }

    function safeCallStatic(className, methodName, args) {
      try {
        var Cls = Java.use(className);
        if (Cls[methodName]) {
          try {
            var res = Cls[methodName].apply(null, args || []);
            return { ok: true, res: res };
          } catch (e2) {
            return { ok: false, err: 'call_failed: ' + e2 };
          }
        } else {
          return { ok: false, err: 'method_not_found' };
        }
      } catch (e) {
        return { ok: false, err: 'class_not_found' };
      }
    }

    // List of Java/Android crypto-related classes and packages to check.
    // Includes Jetpack/Tink, Bouncy/Spongy, SQLCipher, Facebook Conceal, Conscrypt, libsodium wrappers, etc.
    var classesToCheck = [
      // standard Java Enc
      'javax.crypto.Cipher',
      'javax.crypto.spec.SecretKeySpec',
      'java.security.KeyStore',
      'java.security.Security',

      // Shared pref Enc
      'androidx.security.crypto.EncryptedSharedPreferences',
      'androidx.security.crypto.EncryptedFile',
      'androidx.security.crypto.MasterKeys',

      // Google ENC
      'com.google.crypto.tink.KeysetHandle',
      'com.google.crypto.tink.Aead',
      'com.google.crypto.tink.aead.AeadConfig',

      // Bouncy Castle (Not common, but good for checking)
      'org.bouncycastle.jce.provider.BouncyCastleProvider',
      'org.bouncycastle.crypto.engines.AESEngine',
      'org.spongycastle.jce.provider.BouncyCastleProvider',
      'org.spongycastle.crypto.engines.AESEngine',

      // SQLCipher Java Lib
      'net.sqlcipher.database.SQLiteDatabase',
      'net.sqlcipher.database.SQLiteOpenHelper',

      // Facebook Enc
      'com.facebook.crypto.Crypto',
      'com.facebook.crypto.keychain.KeyChain',

      // OpenSSL
      'org.conscrypt.Conscrypt',
      'org.conscrypt.OpenSSLProvider',

      // Libsodium Enc Lib (very common and mostly found native layer Enc Lib)
      'org.libsodium.jni.Sodium',
      'com.goterl.lazysodium.LazySodium',
      'com.goterl.lazysodium.LazySodiumJNI',

      // OpenSSL Java wrappers
      'org.apache.harmony.xnet.provider.jsse.OpenSSLProvider',

      // other common Enc Libs
      'okio.ByteString',                 // handles Bytes and is used by many 3rd party Enc
      //'com.squareup.okhttp3.OkHttpClient', // TLS pinning, Uncomment if not already done
      'com.google.android.gms.security.ProviderInstaller', // another security(Enc) provider from google

      // show a physical store of a key
      'android.security.keystore.KeyProperties',
      'android.security.keystore.KeyGenParameterSpec',

      // Tink helper classes
      'com.google.crypto.tink.integration.android.AndroidKeysetManager',

      // less common crypto wrappers
      'com.tozny.crypto.android.AesCbcWithIntegrity', // example third-party wrapper
      'com.scottyab.aescrypt.AESCrypt' // common simple AES wrapper lib
    ];

    console.log('=== STARTING LIBRARY PRESENCE CHECK ===');

    classesToCheck.forEach(function (c) {
      safeCheckClass(c);
    });

    // Extra checks: inspect Security providers (safe, returns array) — may reveal BC/Conscrypt/etc.
    try {
      var Security = Java.use('java.security.Security');
      try {
        var providers = Security.getProviders();
        if (providers) {
          var n = providers.length;
          console.log('[*] java.security.Security.getProviders() returned ' + n + ' providers:');
          for (var i = 0; i < n; i++) {
            try {
              var p = providers[i];
              // provider.toString() or p.getName()
              var name = p.getName ? p.getName() : p.toString();
              console.log('    - provider: ' + name);
              // If provider name matches known libs, record it
              if (name.match(/BouncyCastle|BC|Conscrypt|OpenSSL|AndroidKeyStore/i)) {
                detections.push('provider:' + name);
              }
            } catch (pe) {
              // ignore per-provider errors
            }
          }
        } else {
          console.log('[*] Security.getProviders() returned null/undefined');
        }
      } catch (e) {
        console.log('[!] Could not call Security.getProviders(): ' + e);
      }
    } catch (e) {
      console.log('[!] java.security.Security class not available: ' + e);
    }

    // Try to detect AndroidKeyStore usage via KeyStore.getInstance("AndroidKeyStore") safely
    try {
      var KeyStore = Java.use('java.security.KeyStore');
      try {
        // call getInstance with the AndroidKeyStore name; returns KeyStore or throws
        var ks = KeyStore.getInstance.overload('java.lang.String').call(null, 'AndroidKeyStore');
        if (ks) {
          console.log('[*] AndroidKeyStore class accessible via KeyStore.getInstance("AndroidKeyStore")');
          detections.push('AndroidKeyStore');
        }
      } catch (e) {
        // ignore - not definitive if provider not available or call blocked/sandboxed
        console.log('[-] KeyStore.getInstance("AndroidKeyStore") call failed or not present: ' + e);
      }
    } catch (e) {
      console.log('[-] java.security.KeyStore class not available for AndroidKeyStore check: ' + e);
    }

    // Final summary
    console.log('=== SUMMARY ===');
    if (detections.length === 0) {
      console.log('[!!!] No Java-level crypto libraries (from the checked list) detected.');
      console.log('[!!!] This strongly suggests the app performs encryption in native code (NDK) or uses custom/obfuscated implementations.');
    } else {
      console.log('[+] Detected ' + detections.length + ' potential Java-level crypto indicators:');
      var uniq = {};
      detections.forEach(function (d) { uniq[d] = 1; });
      Object.keys(uniq).forEach(function (k) { console.log('    * ' + k); });
      console.log('[*] If you see Tink / Jetpack / BouncyCastle / EncryptedSharedPreferences / SQLCipher here, expect Java-level crypto.');
      console.log('[*] If you only see providers like "provider:Conscrypt" or generic libs, inspect further.');
    }

    // Helpful advice printed at end
    console.log('=== NEXT STEPS ===');
    console.log(' - If results show none of the above, start inspecting native libraries (.so) under /lib or hook native exports with Frida.');
    console.log(' - If results show one or more libraries, you may want to hook the corresponding Java classes (e.g., com.google.crypto.tink.*, androidx.security.crypto.*) for deeper tracing.');
    console.log(' - This detector is not exhaustive — some apps rename or repack packages (obfuscation). If you know the app uses repackaged libraries, search for common method names or string constants too.');

    // Expose results to global for interactive sessions
    global.__crypto_detector_results = {
      found: detections,
      notFound: notFound,
      timestamp: (new Date()).toString()
    };
  });
} else {
  console.log('[-] Java not available in this process. Attach to an Android app process.');
}
```

### The Outcome:
<img width="632" height="794" alt="image" src="https://github.com/user-attachments/assets/ece1c79b-4a44-4c6a-a08d-f69b2eb78f26" />

### The Synthesis

From the result of the hook, we can attest that the following libraries and their traces are found in the app:

*   `javax.crypto.Cipher`
*   `javax.crypto.spec.SecretKeySpec`
*   `java.security.KeyStore`
*   `java.security.Security`
*   `androidx.security.crypto.EncryptedSharedPreferences`
*   `androidx.security.crypto.EncryptedFile`
*   `androidx.security.crypto.MasterKeys`
*   `org.libsodium.jni.Sodium`
*   `okio.ByteString`
*   `android.security.keystore.KeyProperties`
*   `android.security.keystore.KeyGenParameterSpec`
*   `provider:AndroidOpenSSL`
*   `provider:AndroidKeyStoreBCWorkaround`
*   `provider:BC`
*   `provider:AndroidKeyStore`

### Using the synthesis

Now, here is the thing: it is not only the app's proprietary components but also the third-party libraries they integrated that use encryption. What this meant is that I needed to be systematic about reducing the noise significantly to pinpoint the Java layer encryption that is used primarily by the app.

## Starting with javax.crypto

Java's crypto library is arguably one of, if not the most, known Java encryption libraries. Known by many Java developers (including me) and Android devs, it is the 101 to Java Encryption. It is a low-level library upon which many other more abstract libraries are built. So, my thinking was if the developers of this app, as we have seen many times do, try to create their own custom encryption on the Java layer, there is a good chance that they will be using this library.

### A Little Intro to javax.crypto

With all the weirdness of the Dalvik bytecode, I will try to explain how this library is used, since understanding this is important to understand the decisions I made next. So, there are two major classes in this package: `Ljavax/crypto/Cipher` and `Ljavax/crypto/spec/SecretKeySpec`.

This class is the class that actually does the encryption. It needs three things: a key, a cipher, and raw data that is planned to get encrypted. In Dalvik bytecode, this is how it is built:

#### Ljavax/crypto/Cipher

```smali
const-string v0, "AES/CBC/PKCS5Padding"
invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
move-result-object v0 # v0 now holds the Cipher machine
```

The Cipher class that we built doesn't take a raw key. Instead, it expects a `SecretKeySpec` object that is pre-loaded with the actual key `[B` and `Algorithm`, and that is exactly what `SecretKeySpec` is.

`SecretKeySpec` is built this way:

```smali
invoke-direct {v2, v0, v1}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
```

Then you pass `SecretKeySpec` in the already built Cipher object and start the encryption:

```smali
invoke-virtual {v0,v1,v2}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V
invoke-virtual {v0, v1}, Ljavax/crypto/Cipher;->doFinal([B)[B
```

Now we have two ways to check which part of the app uses these libraries. One, we can look for the usage of the Cipher object by other classes, or, we can look for where `SecretKeySpec` is being used. Looking for `SecretKeySpec` provides more guarantee than looking for Cipher because it is highly likely that the class that is instantiating `SecretKeySpec` is not a hoax and is actually using what `Ljavax/crypto` has to offer. Also, since we are going to do a static text search over the smali code of the app, if we use Cipher, a lot of noise from one class might emerge, as its constructor and its methods are used at least 3 times to do its job. So a lot of false positive noise will emerge, which is something that we are desperately trying to avoid.

### Looking for Ljavax/crypto/spec/SecretKeySpec

Since the way other classes can instantiate a `SecretKeySpec` object is straightforward, I used this simple PowerShell script to do an app-wide search for its presence:

```powershell
Get-ChildItem -recurse -filter "*.smali" | select-string -pattern "Ljavax/crypto/spec/SecretKeySpec;-><init>\(\[BLjava/lang/String;\)V"
```

And as expected, I was greeted with a barrage of hits:

```shell
smali\androidx\media3\datasource\AesFlushingCipher.smali:87:    invoke-direct {p5, p2, v1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali\androidx\media3\datasource\cache\CachedContentIndex$LegacyStorage.smali:149:    invoke-direct {v1, p2, v3},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali\androidx\media3\exoplayer\hls\Aes128DataSource.smali:215:    invoke-direct {v1, v2, v3},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes2\com\alibaba\pdns\o.smali:1430:    invoke-direct {v4, v5, v1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes3\com\apm\lite\c.smali:665:    invoke-direct {p2, p1, v0},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes3\com\appsflyer\internal\AFb1kSDK.smali:52:    invoke-direct {v2, p1, v0},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\com\google\crypto\tink\internal\h.smali:521:    invoke-direct {v2, v1, v3},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\com\ishumei\l111l1111llIl\l1111l111111Il.smali:141:    invoke-direct {v1, p0, v0},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\com\ishumei\l111l1111llIl\l1111l111111Il.smali:166:    invoke-direct {v1, p0, v2},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\com\ishumei\l111l1111llIl\l1111l111111Il.smali:240:    invoke-direct {v1, p0, v2},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\com\megvii\meglive_sdk\a\c.smali:1154:    invoke-direct {v1, p2, v0},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\com\megvii\meglive_sdk\i\n.smali:866:    invoke-direct {v0, p0, v1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\j5\c.smali:1127:    invoke-direct {p2, v1, p0},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\j5\c.smali:1145:    invoke-direct {v1, p2, p0},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\j5\c.smali:1172:    invoke-direct {v1, p1, p0},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\l6\b.smali:91:    invoke-direct {v0, p1, v1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\m6\a.smali:66:    invoke-direct {v0, p1, v1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\okio\Buffer.smali:434:    invoke-direct {v1, p2, p1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\okio\ByteString.smali:1610:    invoke-direct {v1, p2, p1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\okio\HashingSink.smali:239:    invoke-direct {v1, p2, p3},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\okio\HashingSource.smali:232:    invoke-direct {v1, p2, p3},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\okio\SegmentedByteString.smali:1008:    invoke-direct {v1, p2, p1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\w6\d.smali:96:    invoke-direct {v0, p1, v1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\w6\e.smali:158:    invoke-direct {p2, p1, v0},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\w6\f.smali:173:    invoke-direct {p2, p1, v0},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\w6\i.smali:424:    invoke-direct {v5, v6, v7},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\w6\i.smali:602:    invoke-direct {v6, v7, v8},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\w6\s.smali:62:    invoke-direct {v0, p1, v1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes5\b9\g0.smali:619:    invoke-direct {v8, v9, v11},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes5\io\rong\imlib\common\EncryptUtil.smali:272:    invoke-direct {v1, v2, v3},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes5\io\rong\imlib\url\StaticConfig.smali:155:    invoke-direct {v2, p2, v3},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
```

Most of what you see is noise from integrated third-party SDKs (false positives). So, I had to reduce it significantly, and this is the logic that I used to reduce the number from 30 to 12:

*   Rong Cloud, which is used for encrypting chats.
*   `okio` is also an input/output library and probably had nothing to do with our network payload, but we will look at it.
*   Megvii is a Chinese-based facial recognition SDK which is not our interest now, but we will for sure look at it later.
*   `isHumei`, the anti-tamper SDK (that we defeated/bypassed in my previous write-up); the encryption that happens there is for the library's own sake.
*   AppsFlyer is used to send user data and a lot of user analytics. Is it important? I don't know.
*   `smali_classes3\com\apm\lite`, as the name indicates and from what I have looked up, is an app performance manager, which would probably do less with the app's API encryption.
*   `smali\androidx\media3\exoplayer` is also another SDK that is used for streaming and has probably less to do with the business logic of the app.

The final list of suspected core app classes that use this library is:

```shell
smali\androidx\media3\datasource\AesFlushingCipher.smali:87:    invoke-direct {p5, p2, v1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali\androidx\media3\datasource\cache\CachedContentIndex$LegacyStorage.smali:149:    invoke-direct {v1, p2, v3},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\j5\c.smali:1127:    invoke-direct {p2, v1, p0},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\j5\c.smali:1145:    invoke-direct {v1, p2, p0},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\j5\c.smali:1172:    invoke-direct {v1, p1, p0},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\l6\b.smali:91:    invoke-direct {v0, p1, v1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\m6\a.smali:66:    invoke-direct {v0, p1, v1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\w6\d.smali:96:    invoke-direct {v0, p1, v1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\w6\e.smali:158:    invoke-direct {p2, p1, v0},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\w6\f.smali:173:    invoke-direct {p2, p1, v0},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\w6\i.smali:424:    invoke-direct {v5, v6, v7},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\w6\i.smali:602:    invoke-direct {v6, v7, v8},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes4\w6\s.smali:62:    invoke-direct {v0, p1, v1},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
smali_classes5\b9\g0.smali:619:    invoke-direct {v8, v9, v11},Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
```

Still not a small number of obfuscated classes, but much better than having 30 of them.

I have seen multiple times on this app where classes instantiate and call on their methods, but those classes end up being just forgotten artifacts. So before diving into thousands of lines of obfuscated smali code, I decided to do one final assurance check dynamically.

### Finding out with Dynamic Analysis if SecretKeySpec is used

Now, as usual, I had to write a `Frida` script that hooks `SecretKeySpec`. I had the following core characteristics of the hook when I wrote it:

1.  I needed to see the arguments that are being passed to the `SecretKeySpec`; that information could have a use for us later on, like knowing the algorithm that is used, the keys being passed, and so on.
2.  I needed to see the call stack. Knowing `SecretKeySpec` is called has no use for us unless we know which part of the app is responsible for that call (I used Java's Thread class).

This is the hook:

```typescript
/// <reference types="frida-gum" />

// we are going to use this fucntion to handel the mismsutch that happens between java's ByteArray and javascripts `byte[]` ( which pades a negtive number with 1's )
Java.perform(function(){
    console.log("Script loaded");

    // Get a handle on our target object
    const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");

    // We will use Java's call stack to trace the call
    const ThreadClass = Java.use('java.lang.Thread');

    const original_fun = SecretKeySpec.$init.overload('[B', 'java.lang.String');

    original_fun.implementation = function(key: number[], cipher: string){
        let hexedKey = '';
        const cCipher = cipher;

        // Make a copy of the original implementation before overriding; good practice
        const st = ThreadClass.currentThread().getStackTrace();

        for(let i=0; i<key.length; i++){
            /*
            & 0xFF ; bitwise AND, to remove the 32-bit padding on JS byte notation
            .toString(16); changes the number into a base 16 string
            .padStart(2, '0'); is to make sure you don't see a standalone letter or number and pads it with a '0' if it doesn't get mapped to a two-character string.

            */
            hexedKey += (key[i] & 0xFF).toString(16).padStart(2, '0');
        }

        console.log("+ The method is called with the following arguments:");
        console.log("+ CIPHER HEX KEY =====> " + hexedKey);
        console.log("+ CIPHER MODULE ==> " + cCipher);

        console.log("+ The call stack is........");
        // The number 8 here will be the minimum in most cases, so it tracks how far back you want to see the stack.
        console.log("==========================================================================");
        for (var i = 0; i < Math.min(8, st.length); i++) {
            console.log('  ' + st[i].toString());
        }
        console.log("===========================================================================");

        console.log("+ Calling $init");

        original_fun.call(this, key, cipher);
    }
});
```

And the outcome of this hook, without a doubt, proved to me that none of the 12 classes we filtered are active and being used. I have carefully followed almost 400 lines of output, and they all were third-party SDKs, the ones that we filtered out, 18 of them.

The outcome of the hook:
<img width="892" height="710" alt="image" src="https://github.com/user-attachments/assets/e895a36d-d705-4ecf-b5c2-ba853eed6471" />

It is at this moment that I knew I had to change tactics. I had more than 15 libraries to go after in the same way I did with `javax.crypto`, which could most of them end up potentially being third-party SDK encryption hell.

## Switching Strategy

Remember, my focus from the start was not to decrypt all the internal information exchange of the app. What I need is the ability to read the encrypted message between the app and the API. And so I decided to stop what I am doing (going after all the libraries) and look at each `GET` and `POST` packet using `Burp Suite` and see if I can get info that might make my life easier. And spoiler: it did.

This image shows the traffic getting intercepted using Burp Suite:
<img width="1919" height="688" alt="image" src="https://github.com/user-attachments/assets/e2cf8859-d49c-4496-9943-282fb2f92472" />

As you can see, it is a mess; many calls that don't belong to the app are also being intercepted. But we already know from my previous write-up that calls to `api.vshowapi.com` belong to the app. So, I started binge-watching the requests to see if I could get something out of them.

If you look closely into the images, showing the `GET` and `POST` requests from the app, that I have put here, a pattern emerges (don't get hard on yourself if you don't see it, I was able to see it after looking into so many more).
<img width="1909" height="798" alt="image" src="https://github.com/user-attachments/assets/a3761dd7-bd5f-4d3e-a6e7-96d6e1ff7aac" />
<img width="1919" height="831" alt="image" src="https://github.com/user-attachments/assets/00280112-6918-488d-81ca-e7cf16892f81" />
<img width="1910" height="774" alt="image" src="https://github.com/user-attachments/assets/6aaf501f-cd8c-494e-a2bc-c7b1ec2be05e" />
<img width="1917" height="581" alt="image" src="https://github.com/user-attachments/assets/71db4877-c943-4e27-ae67-72006dda2057" />

Look at one of the URL query strings from the `POST` request.

```text
key=host_goto_rank&action=0&msg_id=69467134416ed&_random=rSrn77U8ThHnpWG%2BzVXCg7%2FZbaDvSCiV&_sign=OvAtt4bHlHNxth9PqnZTODje0N00ko2D6fgg9yQo%2Fcgq89GRiFqiRapbbbtmQv6Da7nEeXEuu37qnzWbaUmCt6Vsyuv9nor7eFjNL8NlVxOaBjkeXpWI3sayvHF2w944t1wMuWhrJwO1TA%2B0nw2VYLo%3D&_uid=65282667&p=android&smei_id=BqD%2BelcYg%2FGWNJ%2BvMKz0mOytQ6%2BxQ7iJtStouWFq9%2FEwVZBnmWLjV9RNRiZ%2BU8E2B%2Bmhv06OOYGqBpQOefn9tkg%3D%3D&c=poppo_transsion&v=469&l=en&mcc=63601&vs=5.4.469.0220&uuid=c6ce8b5d65625b78
```

What caught my eye is that in every `REST` request, there are the literal strings `_random` and `_sign`. My hypothesis was that the value that immediately follows `_sign` could be a direct hash of the URL query. It is much longer than a typical hash, but it could maybe be an encryption of the hash or a custom-implemented integrity check. So what this meant was that, if we mess around and tweak the query string, it is highly probable the server will ignore it since it will fail the established check. And I think they are using `_random` to protect users from `CSRF` attacks (they use cookies, you can see from the image), so I will give less emphasis on it.

The reality is, just like any string, the string `_sign` has to be concatenated with the rest of the query. And there are two possibilities for this:

1.  The literal string `_sign` exists in the app.
2.  Or the string is built on runtime (if this is the case, it will make things a bit complicated, but not a deal-breaker).

I used this one-liner PowerShell script to find all the places where the string `_sign` is stored:

```powershell
Get-ChildItem -Recurse -Filter *.smali | Select-String -Pattern '"_sign"'
```

And the output of the query was:
<img width="1513" height="160" alt="image" src="https://github.com/user-attachments/assets/c83ae3b7-4838-4846-8765-6e6c64389d7d" />

```shell
poppo\smali_classes3\com\androidtool\common\RTCRequestBridge.smali:249:    const-string v4, "_sign"
poppo\smali_classes3\com\androidtool\common\net\EncryptionHelper.smali:782:    const-string v11, "_sign"
poppo\smali_classes3\com\androidtool\common\net\uploadlog\HttpRequestLogHelper.smali:305:    const-string v2, "_sign"
poppo\smali_classes3\com\androidtool\common\troll\util\CustomHttpLoggingInterceptor.smali:3118:    const-string v2, "_sign"
poppo\smali_classes3\com\androidtool\common\troll\util\CustomHttpLoggingInterceptor.smali:3302:    const-string v1, "_sign"
poppo\smali_classes3\com\androidtool\common\troll\util\ReleaseHttpLogger.smali:111:    const-string v2, "_sign"
```

Now, as you can see, a new class that is literally named `EncryptionHelper` is exposed, and I made it my priority target.

## Inside the EncryptionHelper Class

This is what the class looks like:
<img width="1919" height="888" alt="image" src="https://github.com/user-attachments/assets/c9e4bb5a-1e27-47a9-b53e-be7fcc217f8b" />

And as you can see, the class is 1432 smali lines long. But the following are the public classes we are interested in; the private ones are helper methods:

```smali
.method public final decodeApi(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

method public final encodeParams(Ljava/util/Map;)Ljava/util/Map;

.method public final encryptByPublicKeyForSpilt([BLjava/lang/String;)[B

.method public final encodeParams(Ljava/util/Map;)Ljava/util/Map;

.method public final getDiffTime()J and .method public final setDiffTime(J)V
```

So, the string that we searched for `_sign` is present in `encodeParams`. But not only that, it is also using a `libsodium` library, which meant that I was standing at the intersection point between the less security-oriented app and a highly sophisticated native encryption layer. See image:
<img width="1153" height="647" alt="image" src="https://github.com/user-attachments/assets/426087e5-9c4d-40df-9fb6-2918cac1efa5" />
<img width="1040" height="447" alt="image" src="https://github.com/user-attachments/assets/5e309b93-8a57-4a94-974c-41737eca9c1a" />

Now we have identified one of the methods that builds the request. This method is long, but I skimmed around the code, and I think all it does is encrypt the parameters, add the signature, and return a map of parameters that will then be assembled by some other method. So, trying to understand the nitty-gritty detail of how it does this would be a not-so-smart use of my time. We are only interested to know what unencrypted parameters are passed into the method and what the contents of the Map it returns is.

So, the hook that I first wrote was meant to hook all the public methods of this class, but that resulted in a flood of information that was less relevant for what we are doing. You can find that unfiltered hook in the Script section of my GitHub. So, I decided to hook the two most interesting classes: `encodeParams` and `decodeApi`.

## Hooking encodeParams and decodeApi

I wrote the hook so that it satisfies the following requirements:

1.  We need to be able to see what goes in and what goes out of these methods.
2.  Since network calls are multithreaded, without a thread ID, knowing which request belongs to which function call stack will be a mess, since the first call to be completed will be displayed first.
3.  Every call to the methods needs to be registered with a timestamp (will use JS's own helper function). This will help us compare the calls intercepted by `Burp` to what we will see on our console.

This is the hook; it also includes the hook I developed against the anti-tamper mechanism (which runs first).

```typescript
"use strict";

// src/MiniHookEncryptionHelper.ts
Java.perform(
  function() {
    console.log("script loaded");
    function getTimestamp() {
    var today = new Date();
    var time = today.toTimeString().split(' ')[0]; 
    var ms = today.getMilliseconds().toString().padStart(3, '0');
    return time + "." + ms; 
}
    const Application = Java.use("android.app.Application");

    Application.onCreate.implementation = function(){

        this.onCreate();
         try {
      const EncryptionHelper = Java.use("com.androidtool.common.net.EncryptionHelper");
      console.log("Enc lodaed and found");
    const Thread = Java.use("java.lang.Thread");
    console.log("Thread found and loaded");
    const jSString = Java.use("java.lang.String")
    const CommonApp$initSmSdk$1 = Java.use("com.androidtool.CommonApp$initSmSdk$1");
    console.log("+ the class is found and assined with handler");
    const ogDecodeApi = EncryptionHelper.decodeApi;
    const ogEncodeParams = EncryptionHelper.encodeParams;
    // // First run our anti-tamper pass script. The app runs this immediately after startup, so it is logically the first thing that will run.
    const orginalonSuccess = CommonApp$initSmSdk$1.onSuccess; 
    CommonApp$initSmSdk$1.onError.implementation = function(int) {
      console.log(`+ onError is called with the argument ${int}`);
      orginalonSuccess.call(this, "");
      console.log("+ the orginal Onsuccess methode is called ");
    };
    CommonApp$initSmSdk$1.onSuccess.implementation = function(arg) {
      console.log(`+ onSuccess is called with the argument ${arg}`);
      orginalonSuccess.call(this, "");
    };

    EncryptionHelper.decodeApi.implementation = function(firstString, secondString) {
      var date = getTimestamp()
     console.log("[ " + Thread.currentThread().getId() + " ] "+ "[ "+ date + " ]" + "==========================================");
      console.log("[ " + Thread.currentThread().getId() + " ] decodeApi is called, Full detail>>");
      var returned = ogDecodeApi.call(this, firstString, secondString);

      // Commented out this part because the string being passed was too large and filled the console.
     // You can uncomment and use it if needed.
      /*
      console.log("[ " + Thread.currentThread().getId() + " ] frist passed string is: " + firstString);
      console.log("[ " + Thread.currentThread().getId() + " ] second passed string is:" + secondString);
      */
      console.log("[ " + Thread.currentThread().getId() + " ] returned string is:" + returned);
      console.log("[ " + Thread.currentThread().getId() + " ] "+ "[ "+ date + " ]" + "==========================================");
      return returned;
    };
    EncryptionHelper.encodeParams.implementation = function(map) {
      var date = getTimestamp();
      console.log("[ " + Thread.currentThread().getId() + " ] "+ "[ "+ date + " ]" + "==========================================");
      console.log("[ " + Thread.currentThread().getId() + " ] encodeParams is called, Full detail>>");
      var argMap = jSString.valueOf(map);
      var rawRetMap = ogEncodeParams.call(this, map);
      var retMap = jSString.valueOf(rawRetMap);
      console.log("[ " + Thread.currentThread().getId() + " ] Passed Map is : " + argMap);
      console.log("[ " + Thread.currentThread().getId() + " ] Returned Mpa is :" + retMap);
      console.log("[ " + Thread.currentThread().getId() + " ] "+ "[ "+ date + " ]" + "==========================================");
      return rawRetMap;
    };

    } catch (e) {
    console.log("somthing went wrong");
    console.error(e);
  }

    }
   
  }
);
```

The formatted output looks like this. You are able to see from the first image why I only printed the decoded API responses (it is very large text).

<img width="1919" height="938" alt="image" src="https://github.com/user-attachments/assets/06e73d9e-96f1-4e4b-b631-0c7a21bb3081" />

<img width="1919" height="1004" alt="image" src="https://github.com/user-attachments/assets/c417f69c-954d-4c8c-91cb-6cc23818ab70" />

Now one of the calls you can see on the image is:

```text
[ 316 ] [ 15:39:20.400 ]==========================================
[ 316 ] encodeParams is called, Full detail>>
[ 316 ] Passed Map is : {leave_app=0, created_in_action=, created_in_id=, infos=heart_beat|proxy_task|feedback_setting_draw, created_in=}
[ 316 ] Returned Mpa is :{_random=RHOZAerfXMphROU8JNgjIlwrEaA5xXXB, _sign=Ej7PL6S/yvhYw9W9fX20f+IeZeXo2poOEkiAhY0p4chHGFJRTppqXw+i/WICf/zITgVHf92N1fAqGZZYEEaWLRHb5biOLBXVJOAH8EFXXB/73BgjZ9jiyT22REY1NsMg8zDjWBJhqzq/EsIVS/OibEWe08sMYuRxv219egRaBjqClmcunZJKYyIUJASswIhXWiJh0b3lqOIXjy7YZK4siyzeCqEXXZKi1HJUfOCYpd05h3sU}
[ 316 ] [ 15:39:20.400 ]==========================================
```

Now, to make sure this is actually not a hoax call and is legit, let's follow the timestamp and try to find the request that resulted in this being registered in the console. We can't be sure if the request will be captured on `Burp Suite` first or will be displayed on the terminal, but by going around the timestamp `[15:39:20]`ish I found:
<img width="1853" height="839" alt="image" src="https://github.com/user-attachments/assets/dfc903cd-6b05-4e00-9f58-3cfe109b1f77" />
You can see from the image there is a clear match between the two. I did this repeatedly for many other requests and for all of them (all I tried), I have found a perfect match on my terminal. This means the `EncryptionHelper` class is indeed the powerhouse of encryption for this app.

## What this means!

It means one thing: not only are we intercepting the communication between the client and the server, but we are also able to see the bare form of the encrypted information that is being exchanged.

# Conclusion

In this write-up, I have shown how I was able to intercept query parameters that were meant to be encrypted and then sent over the network and get decrypted data from the server by letting the app's own decryption engine do the job and intercepting it as it returned the raw decrypted data.

*Bypassing network encryption was possible because I bypassed TLS pinning in the previous write-up for this app.*
