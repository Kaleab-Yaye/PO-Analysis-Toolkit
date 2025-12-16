/// <reference types="frida-gum" />n
    // gonna use this makes sure we get the key bits in their orginal form, and handels the signed bits as well;

Java.perform(function(){
    console.log("scipt loaded");
    // get handel of the our traget object
    const sKey = Java.use("javax.crypto.spec.SecretKeySpec");
    // we will jav's call stack to trace the call
    const ThreadClass = Java.use('java.lang.Thread');
    

    const orginal_fun = sKey.$init.overload('[B', 'java.lang.String');
    sKey.$init.overload('[B', 'java.lang.String').implementation  = function(key: number[], cypher: string){
    var hexedKey ='';
    const cCypher = cypher;
    // make a copy of the orginal implemenatino before overide ; good pratice
    const st = ThreadClass.currentThread().getStackTrace();
    for(i=0; i<key.length;i++){
        /*
        & ; bitwise and to remove the 32 padding on js byte anotation
        .toString; changes the number in to base 16 string
        .padstart; is to make sure you don see a stand alon letter or numebr and padd it wfrida -U -f com.android.settings -l dist/hello.jsith 0 if it does get mapped to two string

        */
        hexedKey += (key[i] &0xFF).toString(16).padStart(2, '0');
    }





    console.log("+ the methode is called with the follwoing arguments");
    console.log("+ CYPHER HEX KEY =====>" + hexedKey);
    console.log("+ CYPHER MOUDLE ==>" + cCypher);

    console.log("+ the call stack is........")
    // the number 8 here will be min in most cases so, it tracks how far back you want to see the stack
    console.log("==========================================================================")
    for (var i = 0; i < Math.min(8, st.length); i++) console.log('  ' + st[i].toString());
    console.log("===========================================================================")

    console.log("+ calling $init")


    orginal_fun.call(this, key,  cypher);

    }
    
})