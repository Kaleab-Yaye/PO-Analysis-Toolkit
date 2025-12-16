Java.perform(function(){
    console.log("script loaded");
    
    const EncryptionHelper = Java.use("com.androidtool.common.net.EncryptionHelper");
    // we wenna know which thread call a give output on our terminal belongs too (since things happen concurantely)
    const Thread = Java.use('java.lang.Thread');
    // sotring the orginal state and implementation
    const ogEncodeByPublicKey = EncryptionHelper.encodeByPublicKey;
    const ogLoadRsaPublicKey = EncryptionHelper.loadRsaPublicKey;
    const ogDecodeApi = EncryptionHelper.decodeApi;
    const ogEncodeParams = EncryptionHelper.encodeParams;
    const ogEncryptByPublicKeyForSpilt = EncryptionHelper.encryptByPublicKeyForSpilt();
    const ogSetDiffTime = EncryptionHelper.setDiffTime;
    const ogGetDiffTime = EncryptionHelper.getDiffTime;
    //end feilds

    //hook
    
    EncryptionHelper.encodeByPublicKey.implementation = function(rawdata:number [], securityObject: any){
        console.log("[ "+Thread.currentThread().getId()+" ] "+'==========================================');
        console.log("[ "+Thread.currentThread().getId()+" ] "+" encodeByPublicKey is called, Full detail>>");
        var hexedRawData= '';
         for(let i=0; i<rawdata.length;i++){
        /*
        & ; bitwise and to remove the 32 padding on js byte anotation
        .toString; changes the number in to base 16 string
        .padstart; is to make sure you don see a stand alon letter or numebr and padd it wfrida -U -f com.android.settings -l dist/hello.jsith 0 if it does get mapped to two string
rawdata
        */
        hexedRawData += (rawdata[i] &0xFF).toString(16).padStart(2, '0');
    }
     /* you have the falling methodes that you can call on PuclicKey object
     .getEncoded()
     .toString() ( this is what i will use)
     .getFormat()
     .getAlgorithm()
    
    */
   
   var pkInfo = securityObject.toString();
   
    // now we want to call the fucntion and capture the return

    var rawReturend = ogEncodeByPublicKey.call(this,rawdata,securityObject)
    var hexedReturend = '';

     for(let i=0; i<rawReturend.length;i++){
        hexedReturend += (rawReturend[i] &0xFF).toString(16).padStart(2, '0');


    }

    console.log("[ "+Thread.currentThread().getId()+" ] "+ "passed rawdata: "+ hexedRawData);
    console.log("[ "+Thread.currentThread().getId()+" ] "+"passed publickey: "+ pkInfo);
    console.log("[ "+Thread.currentThread().getId()+" ] "+"returned encoded data: "+hexedReturend);
     console.log("[ "+Thread.currentThread().getId()+" ] "+'==========================================')
    
     return rawReturend;
    }

    EncryptionHelper.loadRsaPublicKey.implementation = function(argu: String) {
        console.log("[ "+Thread.currentThread().getId()+" ] "+'==========================================');
        console.log("[ "+Thread.currentThread().getId()+" ] "+"+ loadRsaPublicKey is called, Full detail>>");

        // call the orginal to capture the return
        var publickey = ogLoadRsaPublicKey.call(this, argu);
        var pkInfo = publickey.toString();
        console.log("[ "+Thread.currentThread().getId()+" ] "+ "passed String: "+ argu);
        console.log("[ "+Thread.currentThread().getId()+" ] "+"passed publickey: "+ pkInfo);
        console.log("[ "+Thread.currentThread().getId()+" ] "+'==========================================')

        return publickey;
    }

    EncryptionHelper.decodeApi.implementation = function(firstString:String , secondString:String){
        console.log("[ "+Thread.currentThread().getId()+" ] "+'==========================================');
        console.log("[ "+Thread.currentThread().getId()+" ] "+"decodeApi is called, Full detail>>");
        // call the original
        var returned = ogDecodeApi.call(this,firstString,secondString);
        
        console.log("[ "+Thread.currentThread().getId()+" ] "+"frist passed string is: " + firstString);
        console.log("[ "+Thread.currentThread().getId()+" ] "+"second passed string is:" + secondString);
        console.log("[ "+Thread.currentThread().getId()+" ] "+'==========================================');
        
        return returned;

    


    }

    // this si 1st target, it recives map and returnes map aswell 
    EncryptionHelper.encodeParams.implementation = function(map: any){
        console.log("[ "+Thread.currentThread().getId()+" ] "+'==========================================');
        console.log("[ "+Thread.currentThread().getId()+" ] "+"encodeParams is called, Full detail>>");
        var argMap = map.toString();
        var rawRetMap  = ogEncodeParams.call(this, map);
        var retMap = rawRetMap.toString()
        console.log("[ "+Thread.currentThread().getId()+" ] "+"Passed Map is : " + argMap);
        console.log("[ "+Thread.currentThread().getId()+" ] "+"Returned Mpa is :" + retMap);
        console.log("[ "+Thread.currentThread().getId()+" ] "+'==========================================');

        return rawRetMap;

    }

    EncryptionHelper.encryptByPublicKeyForSpilt.implementation = function (rawData: number[], argString: String){
        console.log("[ "+Thread.currentThread().getId()+" ] "+'==========================================');
        console.log("[ "+Thread.currentThread().getId()+" ] "+"encryptByPublicKeyForSpilt is called, Full detail>>");
        var hexedRawData = '';
        for(let i=0; i<rawData.length;i++){
        hexedRawData += (rawData[i] &0xFF).toString(16).padStart(2, '0');
    }

    var rawRetData = ogEncryptByPublicKeyForSpilt.call(this, rawData, argString)
    var hexedRetData = '';
    for(let i=0; i<rawRetData.length;i++){
        hexedRetData += (rawRetData[i] &0xFF).toString(16).padStart(2, '0');
    }

    console.log("[ "+Thread.currentThread().getId()+" ] "+"passed raw data was: " + hexedRawData);
    console.log("[ "+Thread.currentThread().getId()+" ] "+"passed string value was:" + argString);
    console.log("[ "+Thread.currentThread().getId()+" ] "+"returned raw data was:" + hexedRetData);
    console.log("[ "+Thread.currentThread().getId()+" ] "+'==========================================');

    return rawRetData;

    }

    EncryptionHelper.setDiffTime.implemenatino=function(longNumber: any){
        console.log("[ "+Thread.currentThread().getId()+" ] "+'==========================================');
        console.log("[ "+Thread.currentThread().getId()+" ] "+"setDiffTime is called, Full detail>>");
        console.log("[ "+Thread.currentThread().getId()+" ] "+"passed number is:" + longNumber.toString());
        console.log("[ "+Thread.currentThread().getId()+" ] "+'==========================================');
        ogSetDiffTime.call(this, longNumber);
        return;
        
    

    }

     EncryptionHelper.getDiffTime.implemenatino = function(){
        console.log("[ "+Thread.currentThread().getId()+" ] "+'==========================================');
        console.log("[ "+Thread.currentThread().getId()+" ] "+"getDiffTime is called, Full detail>>");
        var returned = ogGetDiffTime.call(this);
        console.log("[ "+Thread.currentThread().getId()+" ] "+"returned number was:" + returned.toString());
        console.log("[ "+Thread.currentThread().getId()+" ] "+'==========================================');
        return returned;


     }




    



    




})