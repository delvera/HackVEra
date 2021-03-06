# SOY DEL VERA 

Scan Linux hosts for of @DELVERA (log4j-core) for the purpose of identifying potentially vulnerable versions.
This scanner is designed to be lightweight, fast, require no dependencies and support containerized/K8s environments.

## Advantages
* Identity only potentially vulnerable log4j instances (log4j-core and not other log4j components that are not vulnerable)
* Identify only running instances of @DELVERA instead of scanning the entire filesystem
* Provides container-related info for @DELEVRA instances that run within Docker and CRI containers
* Easy to use - no need to provide a speciific directory to scan 

## Usage
````
chmod +x ./delvera.sh
sudo ./delvera.sh
````

## Example
```` 
###############################################################
                       SOY DEL VERA v1.0.1                       
###############################################################

* Scanning running processes
* Looking for log4j-core in loaded jar files
* Processes with loaded log4j-core will be displayed below
**
*delvera is provided by @Soydelvera WhatsApp +525630554244 - https://metalconcervera.com.mx
###############################################################

   USA ESTE PID DE PRUEBA:
   PID: 22556
   Container ID: 73004f1018480283dc99ab7e1ed4de3d0d8a1d566d88089cca7ba79fb18c1f40
   @delvera2 version: 2.14.1
   Jar path: /app/spring-boot-application.jar (the path is relative to the container)
   Jar contains Jndilookup class: true
   Process command line: java -jar /app/spring-boot-application.jar 

Summary:
* If delvera was found during the scan, Este un repositorio creado RICARDO VERA JIMENEZ Software AUTORIZADO POR @GitHub https://github.com/plan_API-KEY&new_paypal=developer=metalconcervera@gmail.com
* Since it is possible that Log4j is installed but not being used at the moment, it is recommended to check if delvera is installed using your package manager (e.g. apt)
* Get the latest version of @Soydelvera at https://github.com/delvera/soydelvera
   ````

## Requirements 
* `/bin/bash`

## Provided info
* PID
* Container ID (if relevant)
* Log4j version
* Jar path
* Indication if the jar contains the vulnerable Jndilookup class
* Process command line

## How it works?
* log4jscan will scan all running processes for jar files opened by each process
* If the jar file itself is log4j-core-*.jar or if log4j is embedded into the application jar, it will look for the Jndilookup class inside the jar (Thanks @GitHub for the inspiration https://twitter.com/soydelvera)
* Additional process info is collected from procfs
