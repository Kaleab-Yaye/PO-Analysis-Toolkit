/// <reference types="frida-gum" />

Java.perform(function () {
  const Activity = Java.use("android.app.Activity");

  // Save the original method handle BEFORE replacing it
  const orig_onResume: any = Activity.onResume; // safe: any[] because signature is unknown

  Activity.onResume.implementation = function (...args: any[]) {
    console.log("[*] onResume hooked for:", this);

    try {
      // Call the ORIGINAL implementation captured above
      return orig_onResume.call(this, ...args);
    } catch (err) {
      // Defensive: log and try alternate calling method if needed
      console.error("[!] error calling original onResume:", err);

      // Try the overload pattern (useful if multiple signatures exist)
      try {
        Activity.onResume.overload().call(this, ...args);
      } catch (err2) {
        console.error("[!] fallback also failed:", err2);
      }
    }
  };
});
