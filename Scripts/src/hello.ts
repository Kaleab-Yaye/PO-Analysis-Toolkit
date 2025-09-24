/// <reference types="frida-gum" />

Java.perform(function(){
    console.log("The script is waiting in safe mode")
    const Activiy = Java.use("android.app.Activity")
    console.log("the handler for th Activity class is set")
    Activiy.onResume.implementation = function(...args : any[]){
        console.log("the implemntation for the onResume funcion is being hooked")
        //now we need to call the orginal methode and this is how you do it.n
        this.onResume.call(this, ...args)


    }


})