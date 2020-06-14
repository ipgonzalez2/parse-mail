MANUAL DE USUARIO

REQUISITOS MÍNIMOS

Para un correcto funcionamiento del sistema, se deben verificar los siguientes requisitos mínimos, de acuerdo con las condiciones en las que se ha ejecutado y probado la aplicación.

Requisitos hardware
•	4.0 GB de RAM.

•	10.0 GB de espacio de almacenamiento.

Requisitos software
•	Sistema operativo Ubuntu 19.10 (eoan) o superior. Aunque BCC ofrece soporte para las versiones xenial, artful y bionic, hasta esta versión el código BPF está muy limitado por el verificador y el programa desarrollado requiere de funcionalidades incluidas a partir de esta versión.

•	Linux kernel versión 5.3 o superior.

MANUAL DE INSTALACIÓN

Como bien se ha dicho en los requisitos, para proceder con la instalación es necesario disponer de un sistema operativo Ubuntu en su versión 19.10 (eoan), que incluye un kernel 5.3, dado que en otras versiones no se da soporte a bucles incluidos en el desarrollo.
Dispuesto un sistema operativo con estas características, donde se ha iniciado sesión, se aporta en el proyecto un fichero install.sh, que se encarga de realizar la instalación de BCC y de la aplicación aquí descrita, ParseMail. Para ejecutar el instalador, es necesario situarse en el directorio donde esté contenido el archivo y desde el terminal ejecutar los siguientes comandos:


$ chmod 755 install.sh

$ sudo ./install.sh


La primera línea simplemente es necesaria para darle permisos de ejecución al script, en caso de que no los tuviese. A continuación, se ejecuta el archivo y comienza la instalación, para la cual es necesario disponer de conexión a Internet, puesto que se realizan numerosas descargas. El proceso puede llevar varios minutos y durante el mismo será requerida en varias ocasiones la confirmación del usuario para poder continuar, siendo necesario introducir S ó Y, según lo que se muestre en la pantalla.

Si todo se ha completado de acuerdo a lo establecido BCC se debería haber instalado bajo la ruta /usr/share/bcc/. Esto puede comprobarse fácilmente listando el directorio en cuestión.

$ cd /usr/share/bcc

$ ls

Como se puede observar, el directorio bcc contiene a su vez otros subdirectorios, entre los cuales se encuentra example, que contiene diferentes carpetas con ejemplos sobre el uso de BCC, donde existe una concreta llamada networking que incluye diferentes aportaciones del uso de eBPF para el control del tráfico en la red y donde se instala la aplicación aquí descrita, bajo el directorio ParseMail. Por tanto, ejecutando el siguiente comando es posible acceder al mismo y mostrar su contenido.


$ cd /usr/share/bcc/examples/networking/ParseMail

$ ls

Si se han seguido correctamente los pasos y el contenido mostrado en el terminal se corresponde con la vista anterior, la instalación debería haberse producido correctamente. El resultado de la misma, además de instalar todo lo relacionado con BCC y eBPF, consiste en un fichero README.md que contiene el manual de usuario que será descrito a continuación, un ejecutable start (cuyo uso se especificará) y un directorio parse-mail que contiene toda la estructura necesaria para el funcionamiento de la aplicación y que no debería ser modificado, salvo las excepciones que serán nombradas en el manual de usuario.


MANUAL DE USO

A continuación, se detalla la manera correcta de proceder al uso del sistema. En primer lugar, para la ejecución del programa es necesario encontrarse en el directorio principal ParseMail. En caso de no ser así, es posible moverse fácilmente al mismo ejecutando el siguiente comando.


$ cd /usr/share/bcc/examples/networking/ParseMail


El contenido incluido en el directorio parse-mail es la base del funcionamiento del programa y contiene un fichero de vital importancia, filters.cfg, que permite la configuración de los parámetros que guiarán la ejecución del programa.

Una vez que se añadan filtros, estos serán registrados en el anterior fichero, cuyo contenido se irá ampliando. Pero, la única parte configurable por el usuario, es la mostrada en la anterior imagen. Así, modificando este fichero, este puede configurar la interfaz que se desee controlar, así como el porcentaje de caracteres que se vayan a comprobar para cada correo. Un 4, el valor establecido por defecto, hace referencia a un porcentaje del 0.04%. A la hora de modificar estos valores es de gran importancia no variar su estructura, ni tocar nada adicional que esté fuera de la sección settings.

El directorio donde la localización debería estar, ParseMail, contiene un ejecutable llamado start, cuya activación supone el inicio del servicio de filtrado. El filtrado se aplica a los correos que estén recogidos en el directorio monitorizado, que se encuentra en la carpeta parse-mail, con el nombre spam. Por tanto, aquellos e-mails que deseen descartarse deben ser añadidos en este directorio.

Antes de iniciar el servicio, es posible añadir los spams que se considere al directorio, ya que el programa comprobará en un principio el contenido del mismo para cargar los filtros correspondientes. En cualquier caso, para activar el servicio, es necesario ejecutar el siguiente comando en el terminal, tras primero haberle concedido al ejecutable los permisos necesarios.


$ sudo chmod 755 start

$ sudo ./start


Como se puede comprobar, es necesario ejecutar el programa con permisos de administrador.

El programa, a pesar de haber cargado los dos filtros presentes en el sistema, continúa ejecutándose dado que debe estar pendiente a los cambios producidos en el directorio monitorizado, que irá reflejando a medida que suceden. Obviamente, si el programa no estuviese ejecutándose, sería posible configurar el directorio spam con los e-mails deseados, y una vez se iniciase el servicio, estos serían configurados. A continuación, se indica como actualizar los spams disponibles mientras el servicio está activo, dado que existen dos movimientos posibles.

Añadir correo para ser filtrado
Para indicarle al programa que un nuevo correo debe comenzar a ser filtrado es tan sencillo como mover el mismo al directorio spam. Por ello, si desde otro terminal, ubicados en el directorio donde existe un nuevo correo spam3 (en este ejemplo el directorio de bienvenida del usuario), lo movemos a la carpeta monitorizada ejecutando el siguiente comando.

$ sudo mv ~ /spam3 \

  /usr/share/bcc/examples/networking/ParseMail/parse-mail/spam


El resultado es que se crea el filtro correspondiente para el correo añadido y se carga en el núcleo, actualizando el número de e-mails que están siendo controlados en ese momento a tres.

Eliminar correo para dejar de ser filtrado
Si, por el contrario, la intención es que un correo deje de ser filtrado, es necesario eliminar el mismo del directorio spam. Es tan sencillo como eliminar, por ejemplo, el correo que acaba de ser añadido, desde otro terminal.

$ sudo rm \

 /usr/share/bcc/examples/networking/ParseMail/parse-mail/spam/spam3

Para detener el sistema es necesario introducir ctrl-c.


