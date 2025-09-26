# defeating-ishumei-anti-fraud-sdk-analysis

# Introduction
In this write-up I will show how I was able to defeat the sophisticated 3rd-party SDK the app uses to check if the device is rooted, if it is an emulator, if Magisk is present on the system. In general this is the center where anti-fraud checks happen, and crippling this SDK results in app-wide vulnerability for various attacks. In this write-up I will show how I achieved it.

# defeating-ishumei-anti-fraud-sdk-analysis
There is another write-up that I did on how I discovered the `ishumei` SDK is the central hub for anti-fraud detection you can look it up; I am not repeating it here. This dossier assumes that you understand why `ishumei` is important for the analysis we will do.

## First encounter with `ishumei` SDK
The ishumei SDK is (probably) a commercial-grade SDK that the PO devs integrated into their app. As you can see from the image below, this is not your typical first RE project it is made and meant to be hostile to anyone who tries to reverse-engineer and understand the inner workings of the SDK.

<img width="1183" height="516" alt="image" src="https://github.com/user-attachments/assets/a01471ed-e8a0-48a9-af89-ccb8bbc55005" />

Going into this SDK with all this obfuscation is not a good use of time. So I had to improvise.

## How is this SDK used by the app?
As I said, to defeat this SDK I can't go through the front door — that is a way too hostile and probably a war I couldn't win (the SDK creators obfuscated it for this exact reason). Instead I had to see how the app uses this SDK.

So I designed a script that searches through the decompiled smali files excluding calls from inside the `ishumei` SDK for any text that resembles the pattern `Lcom/ishumei/`.

```powershell
$searchRoot = "C:\path_to_PO" # The root of the decompiled app files
$excludePath = "$searchRoot\smali_classes*\com\ishumei" # The path we need to ignore to reduce noise from the SDK's own calls
$outputPath = "$searchRoot\ishumei_external_references.txt" # The final intelligence report file (with 5 lines before and after the pattern match was found")

Get-ChildItem -Path $searchRoot -Recurse -Include *.smali -Exclude "$excludePath\*" | Select-String -Pattern "Lcom/ishumei/" -Context 5,5 | Out-File -FilePath $outputPath
```

I expected this SDK to be called from many app classes, but the results clearly showed the calls originate from only one part of the app: `Lcom/androidtool/CommonApp` and inside this class the method calling the SDK is `.method private final initSmSdk()V`.

## Inside the method `initSmSdk()V`
This method is how the app talks to and instantiates the SDK. There are a lot of things that happen in this method, but most are configuration for the SDK. The two most important lines in this method for our analysis are:

```smali
invoke-direct {v1}, Lcom/androidtool/CommonApp$initSmSdk$1;-><init>()V

invoke-static {v1}, Lcom/ishumei/smantifraud/SmAntiFraud;->registerServerIdCallback(Lcom/ishumei/smantifraud/SmAntiFraud$IServerSmidCallback;)V

invoke-static {v1, v0}, Lcom/ishumei/smantifraud/SmAntiFraud;->create(Landroid/content/Context;Lcom/ishumei/smantifraud/SmAntiFraud$SmOption;)Z
```

As you can see, `Lcom/ishumei/smantifraud/SmAntiFraud` is the entry door to the SDK. Since our `initSmSdk()V` only called the two methods within `Lcom/ishumei/smantifraud/SmAntiFraud`, I focused on those.

After taking a good look at their smali files, I concluded the `create()` method is the true entry point and will start the SDK — that is why the app passed many configuration properties into this class. But the `registerServerIdCallback` method revealed something interesting.

### Closer look into `CommonApp$initSmSdk$1`
This is an inner class the compiler generated; in this case it's being used as an implementation for an interface provided by the SDK: `Lcom/ishumei/smantifraud/SmAntiFraud$IServerSmidCallback`. It has two abstract methods:

* `onError(int);`
* `onSuccess(String);`

`CommonApp$initSmSdk$1` provides a concrete implementation of those methods which we will see later.

This signature in the app is a clear indication that the SDK operates on the logic of **callbacks**. The SDK provides the interface and the app tells the SDK through the interface what it needs the SDK to do.

This is a common design you follow when you want to incorporate an SDK into an app, you use callbacks. I am sure the SDK uses this callback to do what the app told it to do but we are not sure if this is the only way the SDK communicates with the app. We have seen that `create()` starts the SDK, but what happens after that inside the SDK is complicated and something we are trying to avoid. We must be sure it is only through **callbacks** that the SDK communicates with the app, meaning we have to make sure the SDK doesn't try to call classes of the app without the callback, which I call "Leaky Abstractions."

So I also designed another script that will search the smali files inside the SDK to make sure there are no "leaky abstractions." The script operates on the following logic:

1. The search has to happen at the root of the SDK.
2. We strategically ignore any call that involves `Lcom/ishumei`.
3. We ignore any lines that involve `invoke-virtual`; this avoids false positives and repeated calls to one class from the SDK, we need to locate the source of that object's creation.
4. We include `invoke-static` and `invoke-direct` (which is usually associated with `<init>`).

```powershell
# === CONFIGURATION ===
# Root folder of the SDK "C:\path	o\smali\com\ishumei"
$rootFolder = "C:\RE\PO\PO\smali_classes4\com\ishumei" 

$outputFile = "C:\RE
ep"

if (Test-Path $outputFile) {
    Clear-Content $outputFile
}

Write-Output "Scanning smali files under: $rootFolder ..."
Get-ChildItem -Path $rootFolder -Recurse -Filter "*.smali" | ForEach-Object {
    $filePath = $_.FullName
    $lineNumber = 0

    # this is how we read the output line by line
    Get-Content $filePath | ForEach-Object {
        $line = $_.Trim()
        $lineNumber++

        # only process invoke-static or invoke-direct as we need it
        # This automatically excludes invoke-virtual and other opcodes
        if ($line -notmatch '^\s*invoke-(static|direct)') { return }

        # the following: even if the line contains invoke-static or invoke-direct,
        # if the being-invoked class is from Lcom/ishumei it will be skipped 
        if ($line -match '^\s*\S+\s+\{[^}]*\},\s+(L[^;]+);') {
            $targetClass = $matches[1]

            # this skips it
            if ($targetClass -like 'Lcom/ishumei*') { return }

            # format the result cleanly with such detail
            $formattedOutput = "[{0}:{1}] {2}" -f $filePath, $lineNumber, $line

            # prints to terminal and saves it.
            Write-Output $formattedOutput
            Add-Content -Path $outputFile -Value $formattedOutput
        }
    }
}

Write-Output "Scan complete"
```

Surprisingly I found zero hits based on this script, and I was confident then that the entire logic of this SDK is handled through the callback `CommonApp$initSmSdk$1`.

Now I had to be sure that this SDK is actually used by the app and is not there as a scarecrow, so I did one more terminal search on this SDK to see if there is any class that will actually call the implementation on the callback object we registered with `registerServerIdCallback()`:

```powershell
Get-ChildItem -Path "C:\RE\PO-RE\PO\smali_classes4\com\ishumei" -Filter "*.smali" -Recurse | Select-String -Pattern "->onSuccess\(", "->onError\("
```

The output for the above search was:

```cmd
..smali_classes4\com\ishumei\l1111l111111Il\l111l1111llIl.smali:230:    invoke-interface {p2, p1}, Lcom/ishumei/smantifraud/SmAntiFraud$IServerSmidCallback;->onError(I)V
..smali_classes4\com/ishumei\l1111l111111Il\l111l1111llIl.smali:315:    invoke-interface {p2, p1}, Lcom/ishumei/smantifraud/SmAntiFraud$IServerSmidCallback;->onError(I)V
..smali_classes4\com/ishumei\l111l11111lIl\l1111l111111Il\l111l1111lIl.smali:884:    invoke-interface {p2,p1}, Lcom/ishumei/smantifraud/SmAntiFraud$IServerSmidCallback;->onSuccess(Ljava/lang/String;)V
..smali_classes4\com/ishumei\smantifraud\SmAntiFraud.smali:928:    invoke-interface {v0, p0}, Lcom/ishumei/smantifraud/SmAntiFraud$IServerSmidCallback;->onSuccess(Ljava/lang/String;)V
```

What this means is that the complex and sophisticated checks done by the `ishumei` SDK boil down to those few classes. Now we could potentially start our tracing within those classes and methods, but since we are planning to also pass the whole thing dynamically, dealing with how the app works with what is passed to the implementation (`onError` and `onSuccess`) suffices for now.

> **Note**: The following explanation will show that the poor handling of the SDK is what made the app susceptible to our attack, not because the SDK is weak and not because we understood all the logic of the SDK.

## How the app implemented the callback
We will start with `onSuccess(Ljava/lang/String;)V`. The reason is `onError`, while the SDK creators made it to be more than just an outlet for logging errors, in this app it is just what `onError` is doing.

### onSuccess
This method takes a string as an argument and the SDK, from what I have seen from dynamic hooks, passes a complicated and encrypted string that was meant to be handled by the app. But the devs of PO only needed the SDK to call `onSuccess` and wanted to handle the logic in a rather lazy but smart way.

A lot happens in `onSuccess`. Most of it are dead ends (decoys the devs put to make things complicated for RE), but there is one method call that means something and results in something persisting: `PreferenceManager.setSmeiId("")` (in smali it is done with registers but to make things clearer I have written it in Java-like form). Whatever argument was passed to `onSuccess`, this method is called with the empty string `""`.

The app uses a `PreferenceManager` class to handle the shared preferences and they define a method `setSmeiId()` to handle and persist things related to the SDK. This method calls the static method on `Landroid/content/SharedPreferences$Editor` which is `putString(key, value)` and passes the value `putString("smei_id", "")`, so the call on `onSuccess()` results in `smei_id` being persisted as `""`. I hypothesized that other parts of the app will access this value in shared preferences to see if the app environment is correct.

The class `PreferenceManager` has another method that is used to access those values stored by `setSmeiId()`, it is `getSmeiId()`. This method goes into the shared preferences and retrieves the value associated with the key `"smei_id"` and returns it.

I did a terminal search app-wide to see if any class calls `getSmeiId()`:

```powershell
PS C:\RE\PO-RE\PO Get-ChildItem -Recurse -File | Select-String -Pattern 'getSmeiId\(\)Ljava/lang/String' -CaseSensitive | ForEach-Object { "$($_.Path):$($_.LineNumber): $($_.Line.Trim())" }
```

The output was:

```terminal
C:\RE\PO-RE\PO\smali_classes3\comndroidtool\CommonApp.smali:1650: invoke-virtual {v1}, Lcom/androidtool/common/data/PreferenceManager;->getSmeiId()Ljava/lang/String;
C:\RE\PO-RE\PO\smali_classes3\comndroidtool\CommonApp.smali:1720: invoke-virtual {v0}, Lcom/androidtool/common/data/PreferenceManager;->getSmeiId()Ljava/lang/String;
```

It then became clearer that the devs of PO used a singleton design to interact with the SDK and the same singleton design (the same class) to interact with what the SDK persists. The method responsible for this, even though you can't see it from the output, is `getSmeiId`.

To ensure this wasn't a dead end I did another terminal search to see how much this method is called; the numerous hits confirmed that it is used by many parts of the app, meaning hooking `onSuccess` can have an app-wide effect. The devs did one last trick: they know the correct value stored in shared preferences regarding the SDK is `("smei_id","")`, but to confuse a reverse-engineer they made it that if `getSmeiId` returns `""` (which `getSmeiId` calls) they log an error (which leads nowhere) and return `""`. This is their last fight because someone who assumed `""` was the right value stored because of a call to `onSuccess` might assume their analysis is wrong if the app is logging an Error.

By doing all that we made sure that a call to `onSuccess` is later acombined by a logic of validation, strengthening our hypothesis that there are no *leaky abstractions* and hooking `onSuccess` could work.

### The onSuccess contingency
Now that we have made sure that `onSuccess` is the main channel where hooks should happen and that we can route any call from `onError` to `onSuccess`, the problem I faced was we don't know how many times `onSuccess` is called and how many times `onError` could be called. My fear was calling `onSuccess` 3 times because `onError` was called three times while `onSuccess` must be called 2 times, that could cause an issue. But upon closer look at what happens when `onSuccess` is called, it became clear that nothing really "app-breaking" could happen from it. This is because when `onSuccess` is called then `setSmeiId("")` is called, calling `setSmeiId` with the same argument overwrites the value stored in shared preferences with the same value, leading to the conclusion that multiple calls to `onSuccess` are **idempotent**.

## The hook
Based on all the analysis I present, I crafted a Frida hook that:

1. Re-routes any calls from `onError` to `onSuccess` with the proper argument after displaying what is passed to `onError` as an argument.
2. Shows how many times `onSuccess` is called and what arguments were passed each time.

Frida hook:

```typescript
Java.perform(function(){
    console.log("the script is loaded");

    try{
        const CommonApp$initSmSdk$1 = Java.use("com.androidtool.CommonApp$initSmSdk$1")
        // if we find the class then the following message should print on the terminal
        console.log("+ the class is found and assigned with handler");
        // now we should store the reference to our original onSuccess, this will give it a new
        // address that frida only knows; it moves it to a new memory address

        const originalOnSuccess = CommonApp$initSmSdk$1.onSuccess;

        // the onError implementation
        CommonApp$initSmSdk$1.onError.implementation = function(int: number){
            console.log(`+ onError is called with the argument ${int}`);
            // we are calling the original onSuccess
            originalOnSuccess.call(this,"")
            console.log("+ the original onSuccess method is called ")
        }

        // the onSuccess implementation to see the args that are passed to our hook
        CommonApp$initSmSdk$1.onSuccess.implementation = function(arg: string){
            console.log(`+ onSuccess is called with the argument ${arg}`)
            // now then we call the original onSuccess
            originalOnSuccess.call(this, "");
        }

    }
    catch(e){
        console.log("something went wrong")
        console.error(e);
    }
})
```

*Note: I didn't use Ghidra for referencing and relied on terminal searches because Ghidra struggled working with how dalvik bytecode relies on indexing for memory referencing.*
