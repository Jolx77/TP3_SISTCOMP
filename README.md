# DESAFIO 1 (UEFI y coreboot):

1) UEFI significa "Unified Extensible Firmware Interface" en inglés. Es un estándar de firmware que reemplaza al BIOS tradicional en muchas computadoras modernas, brindando una interfaz entre el sistema operativo y el hardware para permitir un arranque más rápido y seguro, así como una mayor flexibilidad en la configuración del sistema. Para usar UEFI, generalmente se accede a la configuración del firmware durante el arranque de la computadora, mediante la presión de una tecla específica (como F2, F10, o Del). Desde la configuración UEFI, es posible ajustar diversas opciones relacionadas con el arranque, el hardware y otras configuraciones del sistema. Una función específica que se puede llamar utilizando la dinámica de UEFI es la de configurar el orden de arranque de los dispositivos, útil para cambiar entre sistemas operativos o iniciar desde un dispositivo externo como una unidad USB

2) 
- BlackLotus es el primer malware conocido que puede secuestrar el proceso de arranque de una computadora incluso cuando Secure Boot y otras protecciones avanzadas están habilitadas y se ejecutan en versiones completamente actualizadas de Windows. Es un bootkit UEFI, lo que significa que apunta al UEFI. El peligro de este malware radica en su capacidad para secuestrar el proceso de arranque de una computadora, lo que le permite tomar el control del sistema antes de que se cargue el sistema operativo. Esto significa que puede evadir la mayoría de las medidas de seguridad del sistema operativo, ya que se carga antes de que estas medidas de seguridad estén en su lugar.
Además, BlackLotus es capaz de persistir en el sistema incluso después de que se hayan tomado medidas para eliminarlo, como reinstalar el sistema operativo o reemplazar el disco duro. Esto se debe a que se instala en el firmware UEFI, que no se ve afectado por estas medidas.

- HP anunció la liberación de parches para dos vulnerabilidades de alta gravedad que afectan el firmware UEFI de más de 200 laptops, estaciones de trabajo y otros productos. Las vulnerabilidades, identificadas como CVE-2021-3808 y CVE-2021-3809, podrían permitir la ejecución de código arbitrario en sistemas que ejecutan versiones anteriores del firmware UEFI32.
Estas vulnerabilidades fueron identificadas en ciertos productos de PC de HP que utilizan el firmware AMI UEFI (BIOS del sistema), que podrían permitir la ejecución de código arbitrario. AMI ha lanzado actualizaciones para mitigar las posibles vulnerabilidades1.
Las vulnerabilidades fueron reportadas por TianoCore.org y tienen una puntuación de gravedad de 7.0 según el sistema de puntuación CVSS 3.11. Los identificadores de las vulnerabilidades son CVE-2022-36763, CVE-2022-36764 y CVE-2022-367651.
HP ha identificado las plataformas afectadas y los correspondientes SoftPaqs con versiones mínimas que mitigan las posibles vulnerabilidades. HP recomienda mantener su sistema actualizado con el último firmware y software

3) 
- La Converged Security and Management Engine (CSME) es una tecnología de seguridad y gestión desarrollada por Intel que se encuentra integrada en muchos de sus procesadores, actuando de forma aislada de la CPU. CSME opera en un nivel muy bajo del sistema, incluso por debajo del sistema operativo, y tiene varias funciones importantes:
    - Seguridad: CSME proporciona características de seguridad críticas, como el arranque seguro (Secure Boot), el almacenamiento seguro de claves criptográficas y la protección de la integridad del sistema.
    - Administración Remota: A través de la Converged Security and Management Engine, los administradores de sistemas pueden realizar tareas de gestión remota, como diagnósticos, configuración y actualizaciones de firmware, incluso cuando el sistema operativo principal no está operativo o no está accesible.
    - Gestión de Energía: CSME también desempeña un papel en la gestión eficiente de la energía, ayudando a optimizar el consumo de energía y el rendimiento del sistema.

- El Intel Management Engine BIOS Extension (Intel MEBx), por otro lado, es una extensión del BIOS (Basic Input/Output System)  que integra Intel para la gestión remota y la seguridad en sus procesadores.
    - Configuración Avanzada en la BIOS:
    Intel MEBx proporciona una interfaz gráfica o de texto dentro de la BIOS de la computadora. Esto permite a los administradores de sistemas acceder a configuraciones avanzadas relacionadas con la Intel Management Engine (ME).
    Estas configuraciones incluyen ajustes de seguridad, gestión remota, redes y opciones de energía. Por ejemplo, se puede establecer una contraseña para acceder a la MEBx, configurar la dirección IP para la gestión remota o habilitar funciones como Intel Active Management Technology (AMT) para el control remoto completo del sistema.
    - Gestión Remota y Diagnósticos:
    A través de Intel MEBx, los administradores pueden diagnosticar problemas de hardware o software, incluso cuando el sistema operativo principal no está disponible o no puede arrancar.
    Permite la gestión remota de sistemas, lo que es especialmente útil en entornos empresariales donde se necesitan capacidades de mantenimiento y soporte a distancia.
    - Control de Seguridad:
    MEBx también juega un papel crucial en la seguridad del sistema al permitir la configuración de políticas de seguridad avanzadas. Esto incluye la gestión de certificados digitales, el establecimiento de reglas de autenticación y la configuración de permisos de acceso remoto.
    La capacidad de controlar la MEBx desde la BIOS agrega una capa adicional de seguridad al sistema al proporcionar opciones para proteger la gestión remota y los datos confidenciales almacenados en la Intel Management Engine.

4) Coreboot, anteriormente conocido como LinuxBIOS, es un proyecto de software destinado a reemplazar el firmware propietario (BIOS o UEFI) que se encuentra en la mayoría de los ordenadores. Está diseñado para ser un firmware ligero que realiza solo el número mínimo de tareas necesarias para cargar y ejecutar un sistema operativo moderno de 32 o 64 bits12.
El objetivo de Coreboot es ofrecer las funciones más elementales al inicio del sistema para luego pasar a inicializar el hardware. Después de esta inicialización, comienza la secuencia de arranque del sistema operativo.
Esencialmente, Coreboot es una iniciativa destinada a «abrir» y simplificar el nivel de firmware de los ordenadores modernos. Aunque la mayor parte del software de Coreboot es libre, se requieren blobs binarios para que funcione en algunos dispositivos de hardware. Libreboot es una versión de Coreboot que está completamente libre de blobs y, por tanto, es 100% software libre.
Coreboot es respaldado por la Free Software Foundation (FSF) y su existencia no se basa en una necesidad tecnológica, sino en una ética, ya que para los miembros de la FSF es importante que todo el software del PC sea libre

Algunos de los productos que incorporan coreboot son:
- System76: Esta compañía ha decidido tener un catálogo de portátiles profesionales muy atractivos y potentes para los usuarios profesionales de GNU/Linux. El nuevo Oryx Pro de System76 es el primer portátil que combina Coreboot y NVIDIA1. Este portátil incluye un procesador Intel Core i7-10875H con 8 núcleos físicos, 16 hilos, 2,3GHz de frecuencia base y 5,1GHz de velocidad en modo turbo.

- Fabricantes de placas base: Algunos fabricantes de placas base como MSI, Gigabyte y Tyan han ofrecido Coreboot junto al BIOS propietario estándar o han proporcionado las especificaciones de las interfaces del hardware para algunas de sus placas base recientes.

- Google Chromebooks: Muchos Chromebooks utilizan Coreboot como firmware base debido a su enfoque en la seguridad, la rapidez de arranque y la flexibilidad. 

5) Se ejecuto el codigo helloworld:
![alt text](image.png)