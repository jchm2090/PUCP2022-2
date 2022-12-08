# 1 Introduccion
Malware o “software malicioso” es un término amplio que describe cualquier programa o código malicioso que es dañino para los sistemas. El malware es hostil, intrusivo e intenta invadir, dañar o deshabilitar ordenadores, sistemas informáticos, redes, tabletas y dispositivos móviles, a menudo asumiendo el control parcial de las operaciones de un dispositivo. Al igual que la gripe, interfiere en el funcionamiento normal. Los tipos de malware más comunes son: spyware, adware, bot, ransomware, scareware, rootkit, virus, troyanos y gusanos. [1]

La mayoría de las infecciones se producen cuando realiza sin saberlo una acción que provoca la descarga del malware. Esta acción podría ser un clic en el vínculo de un correo electrónico o la visita a un sitio web malicioso. En otros casos, los hackers extienden el malware mediante servicios peer-to-peer de compartición de archivos y paquetes de descarga de software gratuito. Incrustar malware en un torrent o una descarga popular es una manera efectiva de extenderlo por una base de usuarios más amplia. Los dispositivos móviles también pueden infectarse mediante mensajes de texto. [2]
 
Ciertos ataques, intrusiones y actividades ilícitas no dejan rastros en el disco duro, por lo que sólo será posible encontrar indicios del hecho mediante el análisis de la memoria, por ejemplo identificando qué procesos se estuvieron ejecutando y desde cuándo, que puedan derivar en información relevante para la investigación. [3]

Uno de los principales motivos por los que puede ser necesaria la adquisición del contenido de la memoria RAM de un equipo encendido, es descartar la presencia de malware, el cual puede ocasionar que cierta acción parezca realizada por un usuario del equipo, cuando en realidad es realizada por otro usuario mediante el uso indebido de dicho equipo a distancia. [3]

Este tipo de análisis también permite obtener las claves y contraseñas que estuvieran cargadas en la memoria RAM y que dan indicios de la actividad del usuario.  Otra gran utilidad es el acceso a las claves de cifrado que podrían ser requeridas en el análisis del disco duro del equipo, en caso de que estuviera encriptado. [3]

 
# 2 Descripcion del Problema
## 2.1	Malware Cidrex

Originalmente, Worm.Win32.Cridex era un gusano que se propagaba a través de discos extraíbles que infecta a sistemas operativos Windows. El gusano evolucionó a lo largo de los años hasta convertirse en un malware bancario completo. Las versiones posteriores del malware pueden realizar las siguientes acciones: 
• Inyecciones web 
• Capturas de pantalla y clics (imágenes de páginas web cuando el usuario hace clic en el mouse) 
• Bloquea el acceso a ciertos sitios de Internet • Redirige al usuario de una URL a otra Gusano. 

Win32.Cridex oculta cuidadosamente su servidor de comando y control utilizando una red P2P y un servidor proxy. La comunicación con el servidor de comando y control utiliza cifrado simétrico, más cifrado XOR adicional para el archivo de configuración recibido del servidor de comando y control. [5]
Algunas muestras de CRIDEX emplean el algoritmo de generación de dominios (DGA), lo que hace que las URL a las que accede cambien con el tiempo. Las máquinas infectadas con Cridex también pueden convertirse en esclavas de botnets, participando en comportamientos como ataques DDoS.  [5]

## 2.2	Preguntas del caso

Se realizara el análisis al dump de la memoria RAM de una computadora que se ha visto comprometida por Cridex un malware bancario, es decir, se realizara el análisis del volcado de la memoria del dispositivo infectado con la herramienta Volatility.

## 2.3	Herramientas empleadas para el analisis de volcado de memoria.


•	Vmware – Es un software de virtualización para arquitecturas x86/amd64. Por medio de esta aplicación es posible instalar sistemas operativos conocidos como «invitados», dentro de otro sistema operativo «anfitrión», cada uno con su propio ambiente virtual. [7]

•	Estación de trabajo KALI - Kali Linux es una distribución de Linux de código abierto basada en Debian orientada a diversas tareas de seguridad de la información, como pruebas de penetración, investigación de seguridad, informática forense e ingeniería inversa. [8]

•	Volatility - Es un proyecto open source para el análisis forense. Es un framework Python con muchas librerías que permiten extraer los datos de las memorias volátiles. Su estructura permite desarrollar módulos para extraer los datos específicos de la RAM. [9]

•	Página web virustotal.com - VirusTotal es un sitio web que proporciona de forma gratuita el análisis de archivos y páginas web a través de antivirus. Creada por la empresa Hispasec Sistemas, incluye 55 antivirus y 61 motores de detección en línea. [10]


# 3 Proceso Forense
## 3.1	Proceso de Captura de Evidencia Digital

La captura de evidencia digital consiste en la recopilación de información que pueda servir como evidencia digital en la investigación de un crimen informático. Para la captura de memoria existen las siguientes herramientas para Windows: FTK Imager, DumpIt, Magnet RAM Capture, Belkasoft RAM Capturer, entre otras. Para Linux se suele utilizar LiME (Linux Memory Extractor). El Framework Volatility se puede utilizar tanto en Windows, Linux, Mac y sistemas Android. [3]

Para este caso utilizamos un volcado de memoria infectada con el malware Cidrix, contenida en el repositorio de GitHub en la siguiente dirección web: https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples. [6]

## 3.2	Proceso de Análisis de la Evidencia Digital

Para realizar el análisis del volcado de memoria utilizamos una máquina virtual con la estación de trabajo KALI y utilizamos la herramienta Volatility. A continuación, en línea de comandos verificamos el sistema operativo como primer paso. 

Se observa que el sistema operativo es WinXPSP2x86:

![1](https://user-images.githubusercontent.com/102627887/206274865-b92f1d4d-37da-49c6-b0fc-50fe19bcf1fa.png)

_Fig. 1 Evidencia del sistema operativo de la memoria_

Se puede notar que se utilizó -f, el cual especifica el archivo del volcado de nuestra imagen forense cridex.vmen. Al ejecutar “imageinfo” concluimos que el sistema operativo del usuario es un Windows XP y a partir de ahora podemos hacer uso del (Suggested Profile = WinXPSP2x86) e investigar,
Listamos los procesos que estaban en ejecución cuando se hizo el volcado de memoria con el comando pslist.

![2](https://user-images.githubusercontent.com/102627887/206274883-5c1ed080-121b-4a43-bee0-a1d3da76f7ea.png)

_Fig. 2 Procesos de la memoria en lista_

Asimismo podemos listar los procesos en modo arbol para verificar los procesos dependientes con el comando pstree.
 
![3](https://user-images.githubusercontent.com/102627887/206274899-de5cc08c-dd43-40db-adbf-5bcb673afeba.png)

_Fig. 3 Procesos de la memoria en arbol_

La herramienta tambien nos permite observar cual proceso tiene sesiones establecidas con el comando psxview.

![4](https://user-images.githubusercontent.com/102627887/206274920-e95a437a-2a82-495e-a578-f7863f71e5ee.png)

_Fig. 4 Procesos de la memoria con psxview_

Cada uno de los procesos debe ser investigado, para fines del presente trabajo, nos concentraremos en el proceso con PID 1640 Reader_sl.exe, el cual podemos ubiar a mas detalle su ubicación con el comando cmdline.

![5-1](https://user-images.githubusercontent.com/102627887/206274930-fc015c8c-a35b-4fa1-a120-631057849009.png)
![5-2](https://user-images.githubusercontent.com/102627887/206274947-d94b6cc2-0ced-4814-b189-b35d616d7ecd.png)

_Fig. 5 Proceso PID 1640_

Para el analisis respectivo, se realizara una dump del proceso 1640 con lo cual podremos examinar con mas detalle las caracteristicas de este proceso.

![6](https://user-images.githubusercontent.com/102627887/206274961-eb4f8de9-4de1-4c6c-9176-6908c8efc328.png)

_Fig. 6 Dump men del PID 1640_

Al mismo tiempo, podemos observar con el comando connscan las conexiones TCP establecidas, las cuales son:

![7](https://user-images.githubusercontent.com/102627887/206274978-0f2b81b3-d69d-43b8-9eab-3506d775b3bd.png)

_Fig. 7 Conexiones establecidas_

Usaremos otra herramienta bulk_extractor para extraer las conexiones en un archivo PCAP para ser leido por WireShark.

![8](https://user-images.githubusercontent.com/102627887/206274986-a922b5bb-c0d1-4024-ac2f-260d45541fb4.png)

_Fig. 8 Captura de paquetes con bulk extractor_

Con el uso de la herramienta Wireshark, podemos observar que la IP 41.168.5.140 realiza multiples consultas PSH hacia la PC del usuario, lo cual nos  indica un comportamiento sospechoso:

![9](https://user-images.githubusercontent.com/102627887/206274998-964b9acb-1f9a-4cad-bc1e-be833f037481.jpeg)

_Fig. 9 TCP conexiones_ 

Con el fin de corroborar si esta IP esta ligada al proceso sospechoso PID 1640, del dump obtenido se realizo una busqueda de dicha IP, resultando que efectivamente dicha IP se encuentra ligada al proceso PID 1640.

![10](https://user-images.githubusercontent.com/102627887/206275015-fc9d3666-466f-499a-a70d-cc99fd4c33a1.png)

_Fig. 10 Proceso PID 1640 ligado a la IP 41.168.5.140_ 

Realizamos la extracion del archivo ejecutable de la memoria con el fin de examinarlo con un antivirus, esto se realiza con el comando procdump.

![11](https://user-images.githubusercontent.com/102627887/206275020-86d2f58d-f76f-463c-bc05-5d270c0c8cff.png)

_Fig. 11 Extraccion del proceso PID 1640_ 

Obtenemos el archivo ejecutable exe para ser examinado con algun antivirus.

![12](https://user-images.githubusercontent.com/102627887/206275039-881f09f9-7482-4cc5-9df5-2051e85ac1ba.png)
_Fig. 12 Archivo exe extraido_ 

En la pagina de virustotal.com, podemos concluir que efectivamente el archivo ligado al proceso PID tiene malware asociado a CRIDEX y esta enviando informacion a la IP 41.168.5.140.

 ![13](https://user-images.githubusercontent.com/102627887/206275055-cf6c2c4e-8610-4828-a427-b33b8cd09e46.png)
_Fig. 13 Analisis del archivo con virustotal.com._ 

Con el fin de ubicar al archivo malware en la PC del usuario, usaremos el comando hivelist para listar que archivos hacen uso de la memoria. Se observa que el archivo NTUSER.DAT se ejecuta en varios procesos, por lo cual nos da un indicio de sospecha.

 ![14](https://user-images.githubusercontent.com/102627887/206275071-62f5b910-18a3-4bda-8a92-e6ca65f323f8.png)
 
_Fig. 14 Busqueda del archivo asociado al proceso_

Con el comando printkey al directorio windows “Software/Microsoft/Windows/CurrentVersion/run”, podemos verificar el valor de registro ejectable, el cual es KB00207877.

 ![15](https://user-images.githubusercontent.com/102627887/206275232-b3aa6be9-d2dd-4fc7-828d-4de62d91bfb2.png)
 
_Fig. 15 Identificacion del registro KB00207877_

En el dump de memoria obtenido del proceso PID 1640, podemos verificar que dicho proceso esta asociado al registro KB00207877 encontrado en el archivo NTUSER.DAT, por lo tanto concluimos que pertencen al malware.

 ![16](https://user-images.githubusercontent.com/102627887/206275253-e90b7368-801a-49e9-b211-6af3284565c8.png)
 
_Fig. 16 Dump de memoria asociado a KB00207877_

Verificando el dump de memoria obtenido del proceso PID 1640 identificado como malware CRIDEX, observamos que tambien tiene en su registro multiples dominios bancarios.

![Captura de pantalla de 2022-11-30 08-24-25](https://user-images.githubusercontent.com/102627887/206275334-78bbe0d7-4cc0-49c8-93a5-de6474b5dd00.png)

_Fig. 17 Paginas de bancos en el dump de memoria._

## 3.3	Regla Yara

YARA es una herramienta destinada (pero no limitada a) ayudar la busqueda de malware a travez de reglas definidas. Para el caso de CRIDEX, de acuerdo a lo encontrado, la regla YARA es la siguiente:

```
rule Malware_Cridex_Generic_dll {
	meta:
		description = "Rule matching Cridex Malware"
		date = "2022-12-06"
		reference = "https://ww.virustotal.com/gui/file/5b1361479116041f0126ce82dfd24c4e2c79553b65d3240ecea2dcab4452dcb5"
		hash = "12cf6583f5a9171a1d621ae02b4eb626"

	strings:
		$c1 = "MSVCR80.dll" fullword
		$b2a = "MSVCP80.dll" fullword
		$b2b = "USER32.dll" fullword
	condition:
		$c1 and 1 of ($b*)
}
```

Como podemos observar, las reglas YAR encontraron el malware en el proceso PID 1640  de reader_sl.exe, el cual coincide con nuestro analisis preliminar.

![Imagen 7-12-22 a las 19 40](https://user-images.githubusercontent.com/102627887/206328055-672936c9-9902-4e07-ac1c-ae992727ffb8.jpg)

_Fig. 18 Busqueda con Yala Rule._



# 4 Conclusiones

•	La herramienta Volatility es efectiva para la detección y análisis del malware Cidrex en memoria, incluso permitiria el analisis de otros malware. Para este caso particular, el método utilizado fue analizar procesos y conexiones contenidas en la memoria, para finalmente analizar el volcado de los procesos sospechosos con la página virustotal.com.

•	Para el análisis de malware resulta más efectivo el análisis en memoria que en disco duro por la factibilidad de revisar procesos en ejecución y conexiones establecidas con otros dispositivos en tiempo real.

•	Podemos podríamos concluir que la computadora está infectada por el malware Cidrex.

•	Se encontraron dominios bancarios relacionados con el malware, ademas que existe una conexión abierta a IP 41.168.5.140:8080.

•	El malware utiliza el registro KB00207877 para ejecutar sus proceso, y  esta ligado al archivo NTUSER.DAT.

•	Yara Rule es una herramienta que permite optimizar la busqueda de malware, con las reglas especificas ahorra el trabajo de busqueda respectiva.



# 5 Recomendaciones

Se recomienda explorar el uso de otros comandos que también ofrece el entorno de Volatility, el cual nos permite establecer reglas que hayamos especificado en un archivo y con esto, por ejemplo, podemos indicar que se escaneen todos los procesos de la memoria en busca de patrones de malware especificados.
Igualmente se recomienda actualizar las reglas Yar con cada actualizacion del malware, para que siga siendo identificado.

# 6 Referencias

[1] Sitio web de Netacad, Introducción a la Ciberseguridad. [En línea]. Disponible en: https://www.netacad.com/portal/learning
[2] Sitio web de Avast, ¿Qué es el malware? [En línea]. Disponible en: https://www.avast.com/es-es/c-malware#topic-3
[3] Sitio web de Mendillo, Análisis forense de la memoria RAM. [En línea]. Disponible en: http://mendillo.info/forensica/An%C3%A1lisis%20forense%20de%20la%20memoria%20RAM%20-%20V.%20Mendillo.pdf 
[4] Sitio web de la Microsoft, Botnet: Cidrex. [En línea]. https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=win32%2Fcridex
[5] Sitio web de Documentación de Cidrex. [En línea]. Disponible en https://threats.kaspersky.com/mx/threat/Worm.Win32.Cridex/  [6] Sitio web de GitHub, Memory Samples. [En línea]. Disponible en: https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples
[7] Sitio web de Vmware. [En línea]. Disponible en: https://www.vmware.com
[8] Sitio web de Kali. [En línea]. Disponible en: https://kali.org
[9] Sitio web de Ediciones ENI, Volatility. [En línea]. Disponible en: https://www.ediciones-eni.com/open/mediabook.aspx?idR=554bb28fd9f6e0f97724779646d2a3c8#:~:text=Volatility%20es%20uno%20de%20los,datos%20espec%C3%ADficos%20de%20la%20RAM.
[10] Sitio web de Wikipedia. [En línea]. Disponible en: https://es.wikipedia.org/wiki/VirusTotal

 
