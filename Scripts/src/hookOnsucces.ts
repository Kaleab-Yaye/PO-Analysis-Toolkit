// lets hook the onSuccess methode

import "frida-gum";

Java.perform(function(){
    console.log('[+] the script is waiting in safe mode');

    let hasBeenCalledBefore = false;


    try{
    const CommonApp$initSmSdk$1 = Java.use("com.androidtool.CommonApp$initSmSdk$1");
    //thish will happend if the onSuccess had not been called beofore
    if (hasBeenCalledBefore==false){
        CommonApp$initSmSdk$1.onSuccess.implementation = function(value :string){
            //we have seen that in some cases this.onsucess(value) wont work so as we have seen since the
            //reffrece to the oginal methodes is sotred in the call "call" we will us that
            this.onSuccess.call(this, value);
            
        }
        hasBeenCalledBefore = true;
    }
    else {
        CommonApp$initSmSdk$1.onSucess.implementation = function(value :string){
            console.log('[+] onSuccess had been called before')
            return;
            
    }
    }


    }
    catch(e){
        console.log("[-]" + e)

    }

    

}

)