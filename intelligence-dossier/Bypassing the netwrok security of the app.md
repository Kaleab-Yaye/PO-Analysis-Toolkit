# TL;DR:

So, in this write-up, I will try to demonstrate how I discovered the `Exception Swallowing` bug in an app that has 10 million+ users, specifically regarding its `TrustManager`, and how that let me bypass the `TLS Pinning` implemented by the app.

Here is an overview of how I managed to do exactly that:

The application employed multiple "trust all" `TrustManager` instances. These may have been implemented either as decoys or were genuinely insecure, perhaps because the developers knew that most security-critical communications would not leverage them. The app's developers attempted to implement a clever security measure in their final trust manager, `Lb9/g`, by performing thread-based hostname checks in addition to standard certificate validation. However, in the end, they made a fundamental mistake by swallowing every exception. A rookie mistake? Perhaps. But it ultimately cost them the entire network integrity of the app. The other `SDKs` integrated into the app relied on the system-provided trust manager. This meant they were susceptible to a simple `system trust store injection attack`, as demonstrated.

# Full Walkthrough

In this write-up, I will present how I was able to bypass Poppo Live's TLS/SSL Security.

### Tools I Used
*   **`APK-tool`** to decompile the APK into `smali`
*   My own custom-built register tracking scratchpad
*   **Android emulator** to run the app on
*   **`mitmproxy`**, to intercept requests and bypass TLS
*   A **`Kali VM`** to host `mitmproxy` and to be used as a proxy server.

# Phase One: Understanding How the App Secures Its Connection

Prior to this, in the early phases of RE'ing this app, I noticed the application is heavy on the `okhttp3` library. So, what is this library?
The Google definition goes like this: *OkHttp is an open-source, high-performance HTTP client library for Java and Android applications.*

This library is overwhelmingly used by many apps in the Android ecosystem. We are not interested in how it manages to create a reliable TCP connection or even how a request is built. The only thing that interests us about this library is the question: how does this library handle the TLS handshake?

## OkHttp Library and Network Security
By default, if not configured by the developers, `OkHttp` will use the Android OS-provided `CA` to authenticate the server certificate. If this is the case for the app, then it is much easier to bypass since you can compromise the system trust manager (with Super User privilege) and import your own certificate. The Socket created by this library won't have a problem trusting our certificate.

But as you have guessed, this is not the case with most apps, and probably not with our app. So the question we should be asking is: How does `OkHttp` allow for *TLS Pinning*?

**TLS pinning is a scenario where the developers understand the major security risk of trusting the Android OS's own system CA, and instead provide their own means to verify who the app is talking to.**

To do this, a premature injection of a certificate into the Android trust manager won't work, since a TLS-pinned network will always trust its own algorithm for verifying certificates over the trust manager the Android OS provides.

So, the first thing I did was some digging into how TLS pinning is done in `OkHttp`. Basically, there are two ways for this to happen:
1.  The most straightforward use is to use the `Lokhttp3/CertificatePinner$Builder` class to create a certificate object that is built into the client that is going to make the request.
2.  The developers could use their own trust manager but still use the `OkHttp` library. They would do this:

```java
   OkHttpClient client = new OkHttpClient.Builder()
       .sslSocketFactory(sslSocketFactory, trustManager)
       .build();
```

`OkHttp` is a well-documented library. You can have a look at the Client object and those two builder patterns from here:

*   [https://square.github.io/okhttp/3.x/okhttp/okhttp3/OkHttpClient.Builder.html#sslSocketFactory-javax.net.ssl.SSLSocketFactory-javax.net.ssl.X509TrustManager-](https://square.github.io/okhttp/3.x/okhttp/okhttp3/OkHttpClient.Builder.html#sslSocketFactory-javax.net.ssl.SSLSocketFactory-javax.net.ssl.X509TrustManager-)
*   [https://square.github.io/okhttp/3.x/okhttp/okhttp3/CertificatePinner.html](https://square.github.io/okhttp/3.x/okhttp/okhttp3/CertificatePinner.html)
*   [https://square.github.io/okhttp/3.x/okhttp/okhttp3/OkHttpClient.Builder.html](https://square.github.io/okhttp/3.x/okhttp/okhttp3/OkHttpClient.Builder.html)

### Looking for the CertificatePinner's builder pattern in our target app.
If the app is using the highly optimized TLS pinning object `CertificatePinner`, then to populate the `Client` object, it has to create both objects using their builders. For this, I used the following simple PowerShell script:

```powershell
 Get-ChildItem -Recurse -Filter *.smali | Select-String -Pattern "Lokhttp3/CertificatePinner\$Builder;" | Where-Object { $_.Path -notlike "*\okhttp3\*" }
```

This searches for the use of the pinner object throughout the app but also ignores searches from within the library itself.

But there were zero hits. For an application that uses `OkHttp3` this much, I was not expecting zero hits.

This means one of the following:
1.  The app doesn't have TLS pinning at all.
2.  The app is likely using its own Trust Manager.
3.  The app is trusting the `OkHttp` default trust manager.

Scenarios 1 and 3 are the best-case scenarios for us as they are super easy to bypass. But still, scenario 2 could be true: the app could be using its own `trust manager`.

### Finding custom-built trust managers in our app
Any trust manager, including the one provided by the Android OS and the ones used in the `OkHttp` library, must implement the `Ljavax/net/ssl/X509TrustManager` interface.
Knowing this, we can do this step-by-step:
1.  First, find out if there are custom-built trust managers. If NO, then we know for sure the system-provided trust manager is the only security between us and intercepting the secure network of the app.
2.  If the app utilizes a custom-made trust manager, what we do is track how it is used and try to find a way to bypass it.

So, I did this PowerShell search to see all parts of the app that implement `Ljavax/net/ssl/X509TrustManager`:

```powershell
 Get-ChildItem -Recurse -Filter *.smali | Select-String -Pattern "implements Ljavax/net/ssl/X509TrustManager;" | Where-Object { $_.Path -notlike "*\okhttp3\*" }
```

In this search again, I ignored noise from the `OkHttp3` library since it could have many classes that implement this for different reasons.

The following are the 6 hits that I found:

```
smali_classes2\com\alibaba\pdns\net\HttpTrustManager.smali:6:.implements Ljavax/net/ssl/X509TrustManager;
smali_classes2\com\androidrtc\chat\k.smali:6:.implements Ljavax/net/ssl/X509TrustManager;
smali_classes3\com\androidtool\common\troll\BaseHttpHelper$trustManager$1.smali:6:.implements Ljavax/net/ssl/X509TrustManager;
smali_classes3\com\androidtool\common\utils\DownloadManager$3.smali:6:.implements Ljavax/net/ssl/X509TrustManager;
smali_classes3\com\androidtool\common\utils\image\GlideModule$trustManager$1.smali:6:.implements Ljavax/net/ssl/X509TrustManager;
smali_classes5\b9\g.smali:6:.implements Ljavax/net/ssl/X509TrustManager;
```

So, we now have 6 trust managers (well, 5, as one of them is for Alibaba's own DNS lookup).

Now that we are sure the app is using its own trust managers (6 of them), it makes things hard. But there is one underlying truth of any class that implements `Ljavax/net/ssl/X509TrustManager`, and that is the core logic of checking for certificates legitimacy involves staying quiet if all is good or throwing `java.security.cert.CertificateException` if it doesn't trust the certificates provided. This is handled by one method: `.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V`.

The first thing that I did was rank the trust managers I found based on how critical they look.
I dug more into the `DownloadManager` and the `GlideModule$trustManager$1` classes. Based on what I have seen in most Android implementations they are used for downloading additional stuff and for handling the download of images and videos, so I decided not to look at them first. The reason is, when we are done analyzing the more critical classes, hooked them, and completed our man-in-the-middle attack, if we still see something that is not trusting our certificate, we can easily come back and track their logic. For efficiency, that is better than getting lost inside the `smali` code of a seemingly non-security-critical trust manager.

So here are the main trust managers that I wanted and had to look at:

1.  `smali_classes3\com\androidtool\common\troll\BaseHttpHelper$trustManager$1`: This is the priority target because you can see it is probably being used as the helper that builds the trust manager + `SSLSocketFactory`.
2.  `smali_classes2\com\androidrtc\chat\k.smali`: We don't know what "chat" is in the app. Could it be a real chat? Or something more? It must be looked at.
3.  `smali_classes5\b9\g.smali`: This is last, not because it is less security-critical, but because the package it is in is so obfuscated, I had to prepare myself for the nightmare it might unleash by dealing with the first two, first.

#### First target: `smali_classes3\com\androidtool\common\troll\BaseHttpHelper$trustManager$1;`
I started analyzing its implementation of the abstract method `checkServerTrusted`, and here is what it looks like:

<img width="1824" height="629" alt="image" src="https://github.com/user-attachments/assets/ede6f14b-5960-4743-ae64-d316d25aa8ff" />

```smali
.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 1
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "TrustAllX509TrustManager"
        }
    .end annotation

    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/security/cert/CertificateException;
        }
    .end annotation

    const-string v0, "chain"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullParameter(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "authType"

    invoke-static {p2, p1}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullParameter(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method
```

Well, as you can see, this trust manager's `checkServerTrusted` method basically does nothing; it is crippled by default. It only throws an exception if `p1` is null, which, rest assured, we won't provide it with a null certificate. This means any part of the app that uses this is also contaminated by default. So, we don't even care what part of the app relied on this. But why would the developers create a "trust all" trust manager? Maybe it is code that slipped in from their testing phase? I don't know, but it is a critical vulnerability.

#### Second Target: `smali_classes2\com\androidrtc\chat\k.smali`
Like we did with our first target, we will also look at this class's `checkServerTrusted` method:

<img width="1777" height="885" alt="image" src="https://github.com/user-attachments/assets/fc4eb864-79d1-4bc2-be9c-a4ed15d11a5d" />

```smali
.method public final checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 0

    return-void
.end method
```

Well, surprisingly, this trust manager's method is also a "trust all" manager, like our first target. The fact that two of our priority targets are "trust all" means the developers have probably stuffed all their TLS logic into the heavily obfuscated package: our third target.

#### Third Target: `smali_classes5\b9\g.smali`
The moment I opened the class, I was more than sure that this class is what is holding together the app's logic. Look at the screenshot to have an idea of the amount of things going on in this class.

<img width="1695" height="844" alt="image" src="https://github.com/user-attachments/assets/2c3cbd08-b4d4-44ba-b5d0-6743469a13a1" />

The first thing that caught my eye is that, instead of this trust manager storing the hashed value for `SPKI` (Subject Public Key Information), it was actually storing an `X509Certificate` at the field `a`: `.field public a:Ljava/security/cert/X509Certificate;`.

Now, I could dive into reading the `smali` line by line to see the logic, but what if the app doesn't actually use this trust manager? So I had to make sure that it was an actively integrated class in the `b9` package.

As you guessed, once again I did a terminal search to see where this class is used or instantiated:

```powershell
 Get-ChildItem -Recurse -Filter *.smali | Select-String -Pattern "Lb9/g" | Where-Object { $_.Path -notlike "*\b9\g*" }
```

My first script was without the `Where-Object` after the second pipeline, and this brought many obfuscated class calls like `Lb9/g1`, which added too much noise, so I had to filter it.

The only hits were from:
```
smali_classes5\b9\h.smali:278:    new-instance v1, Lb9/g;
smali_classes5\b9\h.smali:383:    iput-object p1, v1, Lb9/g;->a:Ljava/security/cert/X509Certificate;
```
So the `h` class is the central hub for this trust manager, and it is more likely other parts of the app use this `h` class when they want to build a request. This class will then make sure the connection is carried out with the acknowledgment of this trust manager.

# Phase Two: Reverse Engineering Trust Manager `Lb9/g`
So the `g` trust manager is being used from one other class in the same package, `h`.

First off, `g` is being accessed from one method within `h`, which is `b` (everything in this class is obfuscated, so bear with me). Now `b` takes two things as parameters: `.method public static b(Ljava/net/HttpURLConnection;Ljava/lang/String;)V`.
This was surprising because I was expecting this package to use `OkHttp3`, but instead, they are using something that is the bare metal of all Android-based connections: the `HttpURLConnection` object. It makes sense to make sure your super security-critical communication is handled by this; most won't would suspect it. At the end of `b`, there is an actual call, `p0.getResponseCode()`, which starts the connection. But knowing that barely changes what we have to do. The `HttpURLConnection` has a `setSSLSocketFactory()` that takes an `SSLSocketFactory` as an argument, which means the method `b` has to populate this SSL factory with a trust manager.

I have already done the deep analysis on the `smali` of the `b` method, and here is what happens. I have also analyzed classes that call this static method, so I'll try to summarize it in a way that captures the dance that is happening.

The method receives the `HttpURLConnection` object and a string which is probably in a `PEM` format. Now there is some app's own logic, like a call to the method `Lb9/z0;->d(10)Z`, and if the return is 0, they use the *TLSv1* version; if not, it is *TLSv1.2* to have access to the `SSLContext` (which is used to get the `SSLSocketFactory`).

The next major logic in this method is another call to a static method `invoke-static {p1}, Lb9/z0;->g(Ljava/lang/String;)Z`. Now `p1` is the `PEM` (likely) string, so based on the returned boolean value, the code jumps into conditions.

*   **Condition 0**: If the boolean is zero, then the method does the following (I have put them in an order that makes more sense; what is happening in `smali` is much more abstract):
    1.  First, it gets an instance of `Ljava/security/cert/CertificateFactory` with the call `invoke-static {p1}, Ljava/security/cert/CertificateFactory;->getInstance(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;`.
    2.  It does string manipulation `invoke-virtual {p1}, Ljava/lang/String;->getBytes()[B` on the second parameter, which results in the byte array representation of the string in the default charset (UTF-8).
    3.  It feeds this byte array into the call `Ljava/security/cert/CertificateFactory;->generateCertificate(Ljava/io/InputStream;)Ljava/security/cert/Certificate;`.
    4.  It casts the generated certificate to `X509Certificate` and puts this in the static field `a` of the trust manager `g`.
    5.  It then takes this trust manager and builds the `SSLSocketFactory` with it, then it will set the `SSLSocketFactory` field of the `HttpURLConnection` object (the first parameter) to the newly built `SSLSocketFactory`.

Now it is all done and makes the call. But here is the thing: if we can intercept and hijack the way the byte stream is used to build the certificates, we can use our own certificate string to do this.

*   **Condition 1**: If the boolean is 1, then the method does only one thing: it puts `null` into the static field `a` of the trust manager `g`. (How does the trust manager deal with a null CA?)

Now we have two choices: 1) Try to see where the strings are being loaded from into the method `b`, or 2) We can see how the trust manager handles `null` and see if we can exploit that. The latter seems to be an effective strategy; if we can't take advantage of it, we will fall back to the prior one.

This means we have to dig deep and see the logic of the trust manager `g`'s `checkServerTrusted` method.

## Core logic of the `checkServerTrusted` method in the trust manager
The trust manager's logic in `g` is smart, and it does check two things. (I have done the extra work to go beyond `g` and `h` classes).
When the connection-demanding method in the app prepares its `HttpURLConnection` object, in addition to populating this object with network configurations like these:
```java
httpsConn.setRequestMethod("GET");
httpsConn.setRequestProperty("Authorization", "Bearer ...");
httpsConn.setConnectTimeout(5000); // 5 seconds
```
It also populates the `h` class's `.field public static volatile a:Ljava/util/HashMap;`. The fact that it is `volatile` tells us it has something to do with threads.
The calling method calls `Thread.currentThread().getId()` and puts this ID into the `HashMap` of `h` with the value of the server's `DN` or `CN` it is making the request to.
Since `getResponseCode()` on the `HttpURLConnection` object is blocking, it will be moved to a background thread or coroutines will handle it. We will see how they, in a clever way, used this to harden their security.

Now we are back to the custom-built trust manager's `checkServerTrusted` method. This method, as we have said, takes an array of CA chains as an argument.
*   It first extracts the first certificate in the chain at `[0]`, which is the server's own certificate.
*   Then it calls `Thread.currentThread().getId()`, uses this value, and calls `HashMap.get(id)` on the hash map stored in the class `h`.
*   It then calls `.getIssuerDN()`, which returns a `Ljava/security/Principal`. It does the same for the certificate it is storing in its field `a`, except it calls `getSubjectDN()`.
*   Then it compares the principal of the issuer of the subject certificate that is coming from the internet with the subject principal object of the certificate it was storing in its own field. It does this with `PrincipalObject.equals(PrincipalObject)`.
*   If they are not equal, it throws an exception. That check makes sure the call is happening on the thread it is supposed to happen on, making successful connections thread-locked.

After that check is passed, and after a lot of string manipulation, it extracts the public key of the certificate it is storing in its field.
Then it calls `invoke-virtual {v0, v1}, Ljava/security/cert/Certificate;->verify(Ljava/security/PublicKey;)V`, where `v0` is storing the subject certificate from the internet and `v1` is storing the public key of the certificate it was storing in the field `a`.
Now, if any exception happens in those two steps, the verification fails and the TLS handshake is interrupted. Or so I thought.

The question of what happens if the method `b` on `h` populates the field `a` on the class `g` with `null` instead of an actual certificate drove me to see how the trust manager propagates exceptions up the chain.
And this is the very last line you will fall to if you follow the path of any exception that happened within the execution of `checkServerTrusted`. Look at this:

```smali
:try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 175
    :goto_1
    instance-of p1, p1, Ljava/security/cert/CertificateException;
```

The `catch` jumps to another part of the code, and that also jumps back to `:goto_1`:

```smali
:catchall_0
    move-exception p1

    .line 56
    goto :goto_1
```

Now, as you can see, the very last line you would reach if you follow any exception is `instance-of p1, p1, Ljava/security/cert/CertificateException;`.
This is just a type-safe check and it doesn't throw an exception. This means if the certificate was `null`, then a `NullPointerException` would be swallowed, and the TLS handshake will happen anyway.

***The swallowing of the exception that we just discovered means something more: any exception that is thrown inside this method, including the ones thrown due to a failure to verify certificates, are also swallowed. Now mind you, a trust manager's way of saying "I don't trust this connection, close it" is by throwing an exception that will be caught by the `SSLSocket`, which will then terminate the TLS handshake. But now, if every exception is swallowed, this trust manager is broken. The `SSLSocket` will perform a TLS handshake with any server. All the smart play with threads they did, and probably all this `Lb9/` package does as whole, is compromised by exception swallowing.***

*If all the obfuscated method calls are confusing, you can look at this 1-minute video where I briefly explain the exception swallowing bug.*

<https://drive.google.com/file/d/1bFIocQWM4TOJKdbm2B5UQXBZwfPSv9HD/view?usp=sharing>

## What does this mean?
This means the app is compromised by its own trust manager's exception handling logic, and we are more than sure it will allow any certificate, including the certificate from `mitmproxy` that we will use.

We have managed to see that all the custom-built trust managers of this app are "trust all," some by design and some by mistake. This means we can proxy any connection from the app to `mitmproxy`, and there is a good chance that it will accept the certificate because, unknowingly, they even broke the "delegate CA authorization to the OS first" rule.

# Phase Three: Setting the Right Environment for "The Man-in-the-Middle Attack"
Since the app is going to run on an emulator and the proxy server is my Kali machine, for the setup to work, both of them must be put into bridged mode.

In order to route every connection that our emulator makes to the internet to our VM, we set the global setting `http_proxy` (`settings` is a database with a set of maps `<key, value>`).
The `http_proxy` setting takes a value in the form of `<proxyIp>:<port_number_to_talk_to>`:

```bash
./adb shell settings put global http_proxy <kali_ip>:8080
```

Then, in our Kali's terminal, we run `mitmproxy`. From there, we can start the app and see the traffic and monitor in real-time how `mitmproxy` handles the two-way TLS handshake. Here is a screenshot of the `mitmproxy` real-time read.

<img width="1919" height="529" alt="image (2)" src="https://github.com/user-attachments/assets/e0103368-b6d5-4704-b0f1-dc3bac78de5e" />

As you can probably deduce (even though the image is blurred), all the OK (200) Status Codes are from the app's API. The app's API, as we predicted, is compromised by its own implementation. But if you look at the following screenshot, you can see `mitmproxy` telling us that it couldn't perform the TLS handshake with other parts of the app, which most likely are third-party libraries.

<img width="1485" height="72" alt="502972986-05730ed9-9945-464e-af0a-c26b19d4a377 (1)" src="https://github.com/user-attachments/assets/57a927c8-992d-4e95-ac42-73ff6a6a5f54" />

Now we are more than sure that the SDK shown in the image and other SDKs that were refusing the `mitmproxy` certificate are not using their own trust manager. They are most likely relying on the Android CA trust store. As I said at the beginning, with devices that have root access, it is easy to inject our own certificate. Every part of the device that depended on the system trust store will be compromised. Here are the steps I followed to do so:

1.  The first thing is that the Android trust store saves CAs in a format that is `<hash>.0`. So we can't just put the `mitmproxy.pem` file into the Android system trust store. We need to hash it in the proper way and then put it into the system trust store. **This naming is for optimization by Android. By taking the CN or the DN of the issuer of the certificate it is being asked to verify, it hashes it and then looks if there is any file that matches that hash. This saves lookup time.**
2.  On my Kali machine, I `cd` to `~/.mitmproxy`. In this directory, the certificate for `mitmproxy` is located and it is named `mitmproxy-ca-cert.pem` (this certificate is different from device to device).
3.  To convert this into the format that the Android system trust store can work with, we use the infamous `OpenSSL` library (which is built into Kali machines):
    
    ```bash
    openssl x509 -inform PEM -subject_hash_old -in mitmproxy-ca-cert.pem
    ```

4.  When that command is run, it will result in an 8-character hexadecimal string. We will take that and rename `mitmproxy-ca-cert.pem` to `<hash>.0`, where the hash is the result we found.

Now all that is left is to take this properly renamed certificate and put it into the Android system trust store, which is located at `/system/etc/security/cacerts/`. By default, this system directory is read-only, so you need to:

```bash
adb root
adb remount
```

###### Minor issue with remounting
<img width="657" height="102" alt="image" src="https://github.com/user-attachments/assets/172ac638-632b-4d37-99b4-2ff2d101b115" />

When I tried to remount, even though the `adb` daemon was running as root, it wasn't able to, and I ran into the issue you can see in the image. After looking on the internet why this was the case on the LDPlayer emulator that I was using, I found that the emulator's hypervisor presented the `System.vmdk` as a physically read-only partition to the OS. By making the system disk writable, I was able to write on it.

<img width="778" height="531" alt="image" src="https://github.com/user-attachments/assets/2dadf668-e98b-4bc3-a85a-16d39f9e7140" />

Once remounted, we can put our `.0` file into that directory. The following screenshot will show you what the inside of this highly organized trust store looks like:

<img width="794" height="619" alt="image" src="https://github.com/user-attachments/assets/6bfff6ff-c465-42fc-9dc9-77008d07b2b6" />

Now that I have injected `mitmproxy`'s certificate, what is left is to check if all parties of the app trust our proxy's certificate.

# Phase Four: Conclusion
As you can see from this image, all the `SDKs` of the app, including its own core logic, are trusting our proxy.

<img width="1919" height="998" alt="Untitled design (4) (1)" src="https://github.com/user-attachments/assets/4d1f826a-04cd-493d-a0e6-3bb542bb433b" />
