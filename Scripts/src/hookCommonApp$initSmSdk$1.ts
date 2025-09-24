/// <reference types="frida-gum" />n

Java.perform(function(){
    console.log("the script is loaded");

    try{
        const CommonApp$initSmSdk$1 = Java.use("com.androidtool.CommonApp$initSmSdk$1")
        // if we find the class then the follwoing message shoudl print on the terminal
        console.log("+ the class is found and assined with handler");
        //now we shoudl store the reffernce to our orginalonSuccess, this will give it a new
        //adress that frida only kows it MOVEs it to a new memeroy adress

        const orginalonSuccess = CommonApp$initSmSdk$1.onSuccess;

        //the onError implimentation

        CommonApp$initSmSdk$1.onError.implementation = function(int: number){
            console.log(`+ onError is called with the argument ${int}`);
            //we are calling the orginal onSuccess
            orginalonSuccess.call(this,"")
            console.log("+ the orginal Onsuccess methode is called ")
        }
        // the onSuccess implimentation to see the args that are passed to our hooked

        CommonApp$initSmSdk$1.onSuccess.implementation = function(arg: string){
            console.log(`+ onSuccess is called with the argument ${arg}`)
            //now then we then call the orginall onSuccess
            orginalonSuccess.call(this, "");
        }

    }
    catch(e){
        console.log("somthing went wrong")
        console.error(e);

    }

})