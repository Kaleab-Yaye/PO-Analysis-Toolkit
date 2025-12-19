In this writh up i will show how i was able to read, arguably the most criticall thing, reading the ecrypted call that happens between the app and the API.

# Identifying The Encrption Enviroment of the APP
So, the thing is this time instead of doing static anlysis to find where encryptions happen ( which might envolve writgign scirpts to search text for each potential Encrption `Java/Native` Librayry) i decided to go with
witih dynamic anlysis first to see if the app uses the well know encryption Lyberaries.

Apps, have two ways to enforece encyrption, they can eiser use java layer encryption or native level encryption. and aslo if the encryption is happenig, at native layer, they could easer use there own encrption engine 
written in c or c++ or integrate a 3rd parry native layer ecryption library, those are the possiblies that we have to keep in mind.

## The java layer
the java enrytpiotn layer involves two thigns, a litral JVM  encryption librayes( could be custom or integrated) or Java class that are used as a briged to a native encyrptino that the app might be undergoing.
So, i started looking up the most commen ecyrption realted class and ecyprtion librarries

