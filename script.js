// ===========================================
// Lógica para los Pareos (Matching)
// ===========================================

const matchingsData = [
  {
        "title": "Una la clave del registro de Windows 10 con su descripción. (No se utilizan todas las opciones.)",
        "pairs": [
            {
                "question": "HKEY_CURRENT_USER",
                "answer": "Datos sobre las preferencias del usuario que actualmente inició sesión, incluida la configuración de personalización, los dispositivos predeterminados y los programas, etc."
            },
            {
                "question": "HKEY_CLASSES_ROOT",
                "answer": "Configuración del sistema de archivos, las asociaciones de archivos y los accesos directos que se utilizan cuando le pide a Windows que ejecute un archivo o vea un directorio"
            },
            {
                "question": "HKEY_CURRENT_CONFIG",
                "answer": "Información sobre el perfil de hardware actual de la máquina"
            },
            {
                "question": "HKEY_USERS",
                "answer": "Todos los ajustes de configuración del hardware y el software configurados en la computadora para todos los usuarios"
            }
        ]
  },
  {
        "title": "Coloque los siete pasos definidos en la cadena de destrucción cibernética (Cyber Kill Chain) en el orden correcto.",
        "pairs": [
            {
                "question": "Paso 1",
                "answer": "Reconocimiento"
            },
            {
                "question": "Paso 2",
                "answer": "Armamentización o preparación (weaponization)"
            },
            {
                "question": "Paso 3",
                "answer": "Entrega o distribución (delivery)"
            },
            {
                "question": "Paso 4",
                "answer": "Aprovechamiento (exploitation)"
            },
            {
                "question": "Paso 5",
                "answer": "Instalación"
            },
            {
                "question": "Paso 6",
                "answer": "Comando y control (command and control)"
            },
            {
                "question": "Paso 7",
                "answer": "Acción en objetivos"
            }
        ]
    },
    {
        "title": "Una aplicación cliente necesita finalizar una sesión de comunicación TCP con un servidor. Coloque los pasos del proceso de finalización en el orden en que suceden. (No se utilizan todas las opciones.)",
        "pairs": [
            {
                "question": "Paso 1",
                "answer": "El cliente envía un FIN."
            },
            {
                "question": "Paso 2",
                "answer": "El servidor envía un ACK."
            },
            {
                "question": "Paso 3",
                "answer": "El servidor envía un FIN."
            },
            {
                "question": "Paso 4",
                "answer": "El cliente envía un ACK."
            }
        ]
    },
    {
        "title": "Observe la ilustración. El PC está enviando un paquete al servidor en la red remota. El router R1 está realizando una sobrecarga NAT. Desde la perspectiva de la PC, coincida con el tipo de dirección NAT con la dirección IP correcta.",
        "imageUrl": "images/imagen09.jpg",
        "pairs": [
            {
                "question": "192.0.2.1",
                "answer": "Global interna"
            },
            {
                "question": "203.0.113.5",
                "answer": "Global externa"
            },
            {
                "question": "10.130.5.76",
                "answer": "Local interna"
            }
        ]
    },
    {
        "title": "Una el ataque con la definición.",
        "pairs": [
            {
                "question": "Ampliación y reflexión",
                "answer": "El atacante utiliza resoluciones abiertas para aumentar el volumen de los ataques y ocultar la verdadera fuente del ataque"
            },
            {
                "question": "Envenenamiento de caché de ARP",
                "answer": "El atacante envía información falsificada con el fin de redirigir a los usuarios a sitios maliciosos"
            },
            {
                "question": "Ataque de uso de recursos",
                "answer": "El atacante envía varios paquetes que consumen recursos del servidor"
            }
        ]
    },
    {
        "title": "Haga coincidir la herramienta de monitoreo con su respectiva descripción.",
        "pairs": [
            {
                "question": "NetFlow",
                "answer": "Proporciona estadísticas de paquetes que pasan por un router Cisco o un switch multicapa"
            },
            {
                "question": "SIEM",
                "answer": "Ofrece informes en tiempo real (real-time reporting) y análisis de largo plazo sobre eventos de seguridad."
            },
            {
                "question": "SNMP",
                "answer": "Recupera información sobre el funcionamiento de dispositivos de red"
            },
            {
                "question": "Wireshark",
                "answer": "Captura paquetes y los guarda en un archivo PCAP"
            }
        ]
    },
    {
        "title": "Una el elemento de perfil del servidor con la descripción.",
        "pairs": [
            {
                "question": "puertos de escucha",
                "answer": "Los daemons y puertos TCP y UDP que pueden estar abiertos en el servidor"
            },
            {
                "question": "cuentas de servicio",
                "answer": "Las definiciones del tipo de servicio que una aplicación tiene permitido ejecutar en un host determinado"
            },
            {
                "question": "cuentas de usuario",
                "answer": "Los parámetros que definen el acceso y comportamiento de los usuarios"
            },
            {
                "question": "entorno de software",
                "answer": "Las tareas, los procesos y las aplicaciones que pueden ejecutarse en el servidor"
            }
        ]
    },
    {
        "title": "Una la tecnología o el protocolo de red común con la descripción.",
        "pairs": [
            {
                "question": "Syslog",
                "answer": "Usa el puerto UPD 514 para registrar mensajes de eventos provenientes de terminales y dispositivos de red"
            },
            {
                "question": "NTP",
                "answer": "Utiliza una jerarquía de fuentes horarias autorizadas para enviar información entre dispositivos de la red"
            },
            {
                "question": "ICMP",
                "answer": "Utilizado por los atacantes para identificar los hosts en una red y la estructura de la red"
            },
            {
                "question": "DNS",
                "answer": "Utilizado por los atacantes para exfiltrar los datos en tráfico que se ocultan como consultas normales del cliente"
            }
        ]
    },
    {
        "title": "Una la superficie de ataque con su respectiva descripción de ataque.",
        "pairs": [
            {
                "question": "Superficie de ataque del Software",
                "answer": "Estos ataques son llevados a cabo mediante el aprovechamiento de vulnerabilidades web, en la nube o de aplicaciones de software basado en hosts"
            },
            {
                "question": "Superficie de ataque humana",
                "answer": "Estos ataques incluyen ingeniería social, comportamiento malicioso de recursos internos de confianza y errores de los usuarios."
            },
            {
                "question": "Superficie de ataque de la Red",
                "answer": "Estos ataques incluyen protocolos de redes alámbricas e inalámbricas, así como otros protocolos inalámbricos que usen los teléfonos inteligentes o dispositivos de IoT. Estos ataques apuntan a vulnerabilidades en la capa de transporte."
            }
        ]
    },
    {
        "title": "Haga coincidir la aplicación de firewall basada en host Linux con su respectiva descripción.",
        "pairs": [
            {
                "question": "nftables",
                "answer": "Esta es una aplicación que les permite a los administradores de sistemas de Linux configurar reglas de acceso a la red que forman parte de los módulos de Netfilter del kernel de Linux."
            },
            {
                "question": "TCP Wrappers",
                "answer": "Este es un sistema de registro y control de acceso basado en reglas para Linux Packet filtering basado en direcciones IP y servicios de red."
            },
            {
                "question": "iptables",
                "answer": "Esta aplicación utiliza una máquina virtual simple en el kernel de Linux donde se ejecuta el código y los paquetes de red son inspeccionados."
            }
        ]
    },
    {
    "title": "Una las herramientas de ataque con su respectiva descripción.",
    "pairs": [
      {
        "question": "Nmap",
        "answer": "Es una herramienta de escaneo de red utilizada para sondear dispositivos de red, servidores y hosts para puertos TCP o UDP abiertos."
      },
      {
        "question": "RainbowCrack",
        "answer": "Es utilizada para realizar un hackeo de contraseñas ya sea quitando la contraseña original (después de eludir la encriptación de datos) o directamente averiguando la contraseña."
      },
      {
        "question": "Yersinia",
        "answer": "Es una herramienta de fabricación de paquetes que se utiliza para sondear y probar la solidez de un firewall usando paquetes especialmente diseñados."
      }
    ]
  },
  {
    "title": "Una la política de seguridad con su respectiva descripción. No se utilizan todas las opciones.",
    "pairs": [
      {
        "question": "Política de acceso remoto",
        "answer": "Identifica cómo los usuarios remotos pueden obtener acceso a la red y qué elementos están disponibles a través de la conectividad remota."
      },
      {
        "question": "Política de uso aceptable (AUP)",
        "answer": "Identifica las aplicaciones de red y los usos que son aceptables por la organización"
      },
      {
        "question": "Política de identificación y autenticación",
        "answer": "Especifica las personas autorizadas que pueden acceder a los recursos de red y a los procedimientos de verificación de identidad."
      },
      {
        "question": "Política de mantenimiento de la red",
        "answer": "Especifica los sistemas operativos de los dispositivos de la red y los procedimientos de actualización de las aplicaciones de los usuarios finales."
      }
    ]
  },
  {
    "title": "Después de que el host A recibe una página Web del servidor B, el host A finaliza la conexión con el servidor B. Una cada paso con su respectiva opción en el proceso de terminación normal para una conexión TCP.",
    "pairs": [
      {
        "question": "Paso 1",
        "answer": "El host A envía un FIN al servidor B."
      },
      {
        "question": "Paso 2",
        "answer": "El servidor B envía un ACK al host A."
      },
      {
        "question": "Paso 3",
        "answer": "El servidor B envía un FIN al host A."
      },
      {
        "question": "Paso 4",
        "answer": "El host A envía un ACK al servidor B."
      }
    ]
  },
  {
    "title": "Haga coincidir el servicio de red con su respectiva descripción",
    "pairs": [
      {
        "question": "SNMP",
        "answer": "Permite que los administradores controlen nodos de red"
      },
      {
        "question": "Syslog",
        "answer": "Notifica al administrador con mensajes del sistema detallados"
      },
      {
        "question": "NTP",
        "answer": "Sincroniza el tiempo en todos los dispositivos en la red"
      },
      {
        "question": "NetFlow",
        "answer": "Proporciona estadísticas sobre los paquetes IP que pasan a través de un dispositivo de red."
      }
    ]
  },
  {
    "title": "Una un vector de ataque con su descripción.",
    "pairs": [
      {
        "question": "medios",
        "answer": "Se inicia en el almacenamiento externo"
      },
      {
        "question": "desgaste",
        "answer": "Utiliza fuerza bruta contra dispositivos o servicios"
      },
      {
        "question": "correo electrónico",
        "answer": "Se inicia en un adjunto de correo electrónico"
      },
      {
        "question": "web",
        "answer": "Se inicia en una aplicación de sitio web"
      }
    ]
  },
  {
    "title": "Haga coincidir la clasificación de alertas con la descripción.",
    "pairs": [
      {
        "question": "falso positivo",
        "answer": "El tráfico normal se identifica incorrectamente como una amenaza"
      },
      {
        "question": "negativo verdadero",
        "answer": "El tráfico normal no se identifica como una amenaza"
      },
      {
        "question": "falso negativo",
        "answer": "El tráfico malicioso no se identifica como una amenaza"
      },
      {
        "question": "positivo verdadero",
        "answer": "El tráfico malicioso es identificado correctamente como una amenaza"
      }
    ]
  },
  {
    "title": "Una la métrica SOC con su respectiva descripción.",
    "pairs": [
      {
        "question": "MTTD",
        "answer": "Tiempo promedio que le toma al personal del SOC identificar que se han producido incidentes de seguridad válidos en la red."
      },
      {
        "question": "MTTR",
        "answer": "Tiempo promedio que tarda en detenerse y remediarse un incidente de seguridad."
      },
      {
        "question": "MTTC",
        "answer": "El tiempo necesario para detener el incidente y evitar que cause más daños a los sistemas o datos."
      }
    ]
  },
  {
    "title": "Haga coincidir la función SIEM con su respectiva descripción.",
    "pairs": [
      {
        "question": "Análisis Forense",
        "answer": "Busca registros y eventos de orígenes de toda la organización para un análisis completo de la información"
      },
      {
        "question": "correlación",
        "answer": "Acelera la detección de las amenazas de seguridad y la reacción ante ellas al examinar los registros y los eventos de diferentes sistemas"
      },
      {
        "question": "Agregación",
        "answer": "Reduce el volumen de datos de eventos mediante la consolidación de registros de eventos duplicados"
      },
      {
        "question": "Elaboración de informes",
        "answer": "Presenta datos de eventos acumulados en monitoreo en tiempo real y resúmenes de largo plazo"
      }
    ]
  },
  {
    "title": "Haga coincidir la herramienta de (Security Onion) con su respectiva descripción",
    "pairs": [
      {
        "question": "Snort",
        "answer": "Sistema de detección de intrusiones basado en red (Network-based IDS NIDS)"
      },
      {
        "question": "OSSEC",
        "answer": "Sistema de detección de intrusiones basado en hosts (Host-based Intrusion Detection System HIDS)"
      },
      {
        "question": "Wireshark",
        "answer": "Aplicación de captura de paquetes"
      },
      {
        "question": "Sguil",
        "answer": "Consola de análisis de ciberseguridad de alto nivel (high-level cybersecurity analysis console)"
      }
    ]
  },
  {
    "title": "Haga coincidir la secuencia correcta de pasos que suele tomar un atacante que lleva a cabo un ataque de Domain shadowing.",
    "pairs": [
      {
        "question": "Comprometer al sitio web",
        "answer": "Paso 1"
      },
      {
        "question": "Utilizar el redireccionamiento HTTP 302 (cushioning HTTP 302).",
        "answer": "Paso 2"
      },
      {
        "question": "Utilizar Domain shadowing",
        "answer": "Paso 3"
      },
      {
        "question": "Crear una página que contenga un kit de ataque (exploit kit).",
        "answer": "Paso 4"
      },
      {
        "question": "Propagar el malware a través de una payload (carga dañina).",
        "answer": "Paso 5"
      }
    ]
  },
  {
    "title": "Una la categoría del ataque con su respectiva descripción. No se utilizan todas las opciones.",
    "pairs": [
      {
        "question": "DoS",
        "answer": "Puede bloquear aplicaciones o servicios de red. También puede saturar una computadora o toda la red con tráfico hasta que se apaguen por sobrecarga."
      },
      {
        "question": "Ataque de analizador de protocolos",
        "answer": "Utiliza una aplicación o un dispositivo que puede leer, monitorear y capturar intercambios de datos en la red y leer paquetes de red."
      },
      {
        "question": "MITM",
        "answer": "Ocurre cuando los atacantes se han posicionado entre un origen y un destino para monitorear, obtener y controlar la comunicación de manera transparente."
      }
    ]
  },
  {
    "title": "Haga coincidir la solución antimalware basada en la red con la función. (No se utilizan todas las opciones).",
    "pairs": [
      {
        "question": "control de admisión de red",
        "answer": "permite que solo los sistemas autorizados y compatibles se conecten a la red"
      },
      {
        "question": "protección avanzada contra malware",
        "answer": "proporciona protección a los terminales contra virus y malware"
      },
      {
        "question": "dispositivo de seguridad web",
        "answer": "proporciona filtrado de sitios web y listas de bloqueo antes de que lleguen al punto final"
      },
      {
        "question": "dispositivo de seguridad de correo electrónico",
        "answer": "permite filtrar el SPAM y los correos electrónicos potencialmente maliciosos antes de que lleguen al punto final"
      }
    ]
  },
  {
    "title": "Haga coincidir los comandos CLI Linux con la función que corresponda.",
    "pairs": [
      {
        "question": "ls",
        "answer": "muestra los archivos dentro de un directorio"
      },
      {
        "question": "rm",
        "answer": "elimina archivos"
      },
      {
        "question": "mkdir",
        "answer": "crea un directorio en el directorio actual"
      },
      {
        "question": "man",
        "answer": "muestra la documentación para un comando específico"
      },
      {
        "question": "cd",
        "answer": "cambia el directorio actual"
      }
    ]
  },
  {
    "title": "Una el tipo de entrada de la tabla de enrutamiento de red de destino con una definición.",
    "pairs": [
      {
        "question": "ruta dinámica",
        "answer": "Se agrega cuando un protocolo como OSPF o EIGRP detecta una ruta"
      },
      {
        "question": "interfaz conectada directamente",
        "answer": "Se agrega automáticamente cuando una interfaz está configurada y activa"
      },
      {
        "question": "ruta estática",
        "answer": "El administrador de red la configura manualmente"
      },
      {
        "question": "interfaz de ruta local",
        "answer": "Sólo se encuentra en enrutadores que ejecutan enrutamiento IOS 15+ o IPv6"
      }
    ]
  },
  {
    "title": "Una la organización de seguridad con su respectiva función de seguridad. No se utilizan todas las opciones.",
    "pairs": [
      {
        "question": "FIRST",
        "answer": "Reúne a una variedad de equipos de respuesta ante incidentes de seguridad informática del gobierno, organizaciones comerciales y educativas para fomentar la colaboración y la coordinación en el uso compartido de información, la prevención de incidentes y la reacción rápida."
      },
      {
        "question": "MITRE",
        "answer": "Mantiene una lista de vulnerabilidades y exposiciones comunes (CVE)."
      },
      {
        "question": "SANS",
        "answer": "Mantiene y apoya al Internet Storm Center y también desarrolla cursos de seguridad."
      }
    ]
  },
  {
    "title": "Una la supervisión de datos de red con su respectiva descripción.",
    "pairs": [
      {
        "question": "Datos de la transacción",
        "answer": "Incluye servidor específico del dispositivo y registros de host"
      },
      {
        "question": "Datos de la sesión",
        "answer": "Contiene los detalles de los flujos de red, incluyendo las 5 tuplas, la cantidad de datos transmitidos y la duración de la transmisión de datos."
      },
      {
        "question": "Datos de alerta",
        "answer": "Generado por dispositivos IPS o IDS cuando se detecta tráfico sospechoso"
      },
      {
        "question": "Datos estadísticos",
        "answer": "Utilizado para describir y analizar el flujo de red o el rendimiento de los datos"
      }
    ]
  },
  {
    "title": "Una las partes interesadas en un incidente de seguridad con su rol.",
    "pairs": [
      {
        "question": "departamento de asuntos legales",
        "answer": "Revisa las políticas para las infracciones a pautas locales o federales"
      },
      {
        "question": "recursos humanos",
        "answer": "Adopta medidas disciplinarias"
      },
      {
        "question": "departamento de TI",
        "answer": "Preserva la evidencia de un ataque"
      },
      {
        "question": "protección de la información",
        "answer": "Cambia las reglas de firewall"
      },
      {
        "question": "gerencia",
        "answer": "Diseña el presupuesto"
      }
    ]
  },
  {
    "title": "Una una función de la gestión de seguridad con su respectiva descripción.",
    "pairs": [
      {
        "question": "Gestión de riesgos",
        "answer": "Es el análisis comprehensivo del impacto de los ataques en los activos principales de la empresa y su funcionamiento"
      },
      {
        "question": "Administración de vulnerabilidades",
        "answer": "Es la práctica de seguridad fue diseñada para prevenir de manera proactiva el aprovechamiento de vulnerabilidades de TI dentro de una organización."
      },
      {
        "question": "Administración de la configuración",
        "answer": "Es el control del inventario de las configuraciones de sistemas a nivel de hardware y software"
      },
      {
        "question": "Administración de recursos",
        "answer": "Es la implementación de sistemas que rastrean la ubicación y configuración de software de dispositivos conectados a la red a través de toda la empresa"
      }
    ]
  },
  {
    "title": "Una un campo en la tabla de eventos de Sguil con la descripción.",
    "pairs": [
      {
        "question": "cid",
        "answer": "El número de evento único del sensor"
      },
      {
        "question": "ip_proto",
        "answer": "El tipo de protocolo IP del paquete"
      },
      {
        "question": "status",
        "answer": "La clasificación de Sguil asignada a este evento"
      },
      {
        "question": "signature",
        "answer": "El nombre legible humano del evento"
      },
      {
        "question": "marca de hora",
        "answer": "La hora a la que se produjo el evento en el sensor"
      },
      {
        "question": "sid",
        "answer": "El ID único del sensor"
      }
    ]
  },
  {
    "title": "Haga coincidir las pestañas del administrador de tareas de Windows 10 con su respectiva función. No se utilizan todas las opciones.",
    "pairs": [
      {
        "question": "Detalles",
        "answer": "Permite que un proceso tenga su afinidad establecida."
      },
      {
        "question": "Rendimiento",
        "answer": "Muestra información sobre el uso de recursos de la CPU, la memoria, la red, el disco y otros."
      },
      {
        "question": "Servicios",
        "answer": "Permite iniciar, detener o reiniciar un servicio en particular."
      },
      {
        "question": "Inicio",
        "answer": "Permite que se deshabiliten los programas que se están ejecutando en el inicio del sistema."
      }
    ]
  },
  {
    "title": "Una aplicación cliente necesita terminar una sesión de comunicación TCP con un servidor. Coloque los pasos del proceso de terminación en el orden en que ocurrirán. (Se utilizan todas las opciones).",
    "pairs": [
      {
        "question": "Paso 1",
        "answer": "client sends FIN"
      },
      {
        "question": "Paso 2",
        "answer": "server sends ACK"
      },
      {
        "question": "Paso 3",
        "answer": "server sends FIN"
      },
      {
        "question": "Paso 4",
        "answer": "client sends ACK"
      }
    ]
  },
  {
    "title": "Haga coincidir el tipo de datos de monitoreo de red con la descripción.",
    "pairs": [
      {
        "question": "datos estadísticos",
        "answer": "utilizado para describir y analizar el flujo de red o el rendimiento de los datos"
      },
      {
        "question": "datos de la transacción",
        "answer": "incluye servidor específico del dispositivo y registros de host"
      },
      {
        "question": "datos de la sesión",
        "answer": "contiene los detalles de los flujos de red, incluyendo las 5 tuplas, la cantidad de datos transmitidos y la duración de la transmisión de datos"
      },
      {
        "question": "datos de alerta",
        "answer": "generado por dispositivos IPS o IDS cuando se detecta tráfico sospechoso"
      }
    ]
  }


];

const matchingListWrapper = document.getElementById('matching-list-wrapper');
const matchingCheckButton = document.getElementById('matching-check-button');
const matchingShowAnswersButton = document.getElementById('matching-show-answers-button');
const matchingFeedback = document.getElementById('matching-feedback');

// Función para barajar un array
function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

function renderMatchings() {
    matchingListWrapper.innerHTML = '';
    matchingsData.forEach((matchingSet) => {
        const setDiv = document.createElement('div');
        setDiv.classList.add('matching-set');
        
        const title = document.createElement('h3');
        title.textContent = matchingSet.title;
        setDiv.appendChild(title);

        if (matchingSet.imageUrl) {
            const image = document.createElement('img');
            image.src = matchingSet.imageUrl;
            image.alt = matchingSet.title;
            image.classList.add('matching-image');
            setDiv.appendChild(image);
        }

        const shuffledQuestions = shuffleArray([...matchingSet.pairs]);
        const shuffledAnswers = shuffleArray([...matchingSet.pairs]);

        shuffledQuestions.forEach((pair) => {
            const matchingItem = document.createElement('div');
            matchingItem.classList.add('matching-item');
            
            const questionText = document.createElement('p');
            questionText.textContent = pair.question;
            matchingItem.appendChild(questionText);

            const selectList = document.createElement('select');
            selectList.classList.add('matching-dropdown');
            selectList.setAttribute('data-question-text', pair.question);

            const defaultOption = document.createElement('option');
            defaultOption.textContent = "Selecciona una opción";
            defaultOption.value = "";
            defaultOption.disabled = true;
            defaultOption.selected = true;
            selectList.appendChild(defaultOption);

            shuffledAnswers.forEach(answerPair => {
                const option = document.createElement('option');
                option.textContent = answerPair.answer;
                option.value = answerPair.answer;
                selectList.appendChild(option);
            });
            
            matchingItem.appendChild(selectList);
            setDiv.appendChild(matchingItem);
        });

        matchingListWrapper.appendChild(setDiv);
    });
}

function checkMatchings() {
    let allCorrect = true;
    const allDropdowns = document.querySelectorAll('.matching-dropdown');
    let answeredCount = 0;

    allDropdowns.forEach(dropdown => {
        const selectedAnswer = dropdown.value;
        const questionText = dropdown.getAttribute('data-question-text');
        
        dropdown.classList.remove('correct', 'incorrect');

        if (selectedAnswer) {
            answeredCount++;

            // Encuentra el conjunto de pareos al que pertenece este dropdown
            const parentSet = dropdown.closest('.matching-set');
            const setIndex = Array.from(matchingListWrapper.children).indexOf(parentSet);
            const currentMatchingSet = matchingsData[setIndex];

            // Busca la respuesta correcta dentro de ese conjunto específico
            const correctPair = currentMatchingSet.pairs.find(p => p.question === questionText);
            
            if (correctPair && correctPair.answer === selectedAnswer) {
                dropdown.classList.add('correct');
            } else {
                dropdown.classList.add('incorrect');
                allCorrect = false;
            }
        }
    });

    if (answeredCount === allDropdowns.length) {
        if (allCorrect) {
            matchingFeedback.textContent = "¡Todos los pareos son correctos!";
            matchingFeedback.style.color = "green";
        } else {
            matchingFeedback.textContent = "Hay pareos incorrectos. Inténtalo de nuevo.";
            matchingFeedback.style.color = "red";
        }
    } else {
        matchingFeedback.textContent = `Faltan ${allDropdowns.length - answeredCount} pareo(s) por completar.`;
        matchingFeedback.style.color = "orange";
    }
}

function showCorrectAnswers() {
    const allDropdowns = document.querySelectorAll('.matching-dropdown');
    allDropdowns.forEach(dropdown => {
        const questionText = dropdown.getAttribute('data-question-text');

        // Encuentra el conjunto de pareos al que pertenece este dropdown
        const parentSet = dropdown.closest('.matching-set');
        const setIndex = Array.from(matchingListWrapper.children).indexOf(parentSet);
        const currentMatchingSet = matchingsData[setIndex];

        // Busca la respuesta correcta dentro de ese conjunto específico
        const correctPair = currentMatchingSet.pairs.find(p => p.question === questionText);

        if (correctPair) {
            dropdown.value = correctPair.answer;
            dropdown.classList.add('correct');
        }
        dropdown.disabled = true; // Deshabilita los dropdowns después de mostrar las respuestas
    });
    // Deshabilita los botones para evitar re-intentos en el estado de "mostrar respuestas"
    matchingCheckButton.disabled = true;
    matchingShowAnswersButton.disabled = true;
    matchingFeedback.textContent = "Respuestas correctas mostradas.";
    matchingFeedback.style.color = "green";
}

// Event Listeners
matchingCheckButton.addEventListener('click', checkMatchings);
matchingShowAnswersButton.addEventListener('click', showCorrectAnswers);

// Llama a la función al cargar la página
window.addEventListener('load', renderMatchings);


const questions = [

  {
    "question": "¿Qué dos afirmaciones hacen referencia a características de un virus?",
    "options": [
      "Un virus se autorreplica atacando de manera independiente las vulnerabilidades en las redes.",
      "Por lo general, un virus requiere la activación del usuario final.",
      "El virus proporciona datos confidenciales al atacante, como contraseñas.",
      "Un virus tiene una vulnerabilidad habilitante, un mecanismo de propagación y una carga útil.",
      "Un virus puede estar inactivo y luego activarse en un momento o en una fecha en particular."
    ],
    "correct": [
      1,
      4
    ]
  },
  {
    "question": "De las siguientes opciones, ¿cuál señala una característica de un caballo de Troya en lo que se refiere a la seguridad de la red?",
    "options": [
      "Se envían enormes cantidades de datos a una interfaz de dispositivo de red particular.",
      "El malware está alojado en un programa ejecutable aparentemente legítimo.",
      "Se utiliza un diccionario electrónico para obtener una contraseña que se usará para infiltrarse en un dispositivo de red clave.",
      "Se destina mucha información a un bloque de memoria particular, y esto hace que que otras áreas de la memoria se vean afectadas."
    ],
    "correct": [
      1
    ]
  },
  {
    "question": "¿Cuál de las siguientes es una ventaja de adoptar IMAP en lugar de POP para organizaciones pequeñas?",
    "options": [
      "IMAP envía y recupera correo electrónico, pero POP solamente lo recupera.",
      "Cuando el usuario se conecta a un servidor POP, se mantienen copias de los mensajes en el servidor de correo durante un tiempo breve, pero IMAP los mantiene durante un tiempo prolongado.",
      "Los mensajes se mantienen en los servidores de correo electrónico hasta que se eliminan manualmente del cliente de correo electrónico.",
      "POP solo permite que el cliente almacene mensajes de manera centralizada, mientras que IMAP permite el almacenamiento distribuido."
    ],
    "correct": [
      2
    ]
  },
  {
    "question": "¿Cuáles son dos características de ARP? (Escoja dos opciones.)",
    "options": [
      "Si un host está listo para enviar un paquete a un dispositivo de destino local y tiene la dirección IP pero no la dirección MAC del destino, genera una difusión ARP.",
      "Se envía una solicitud ARP a todos los dispositivos de la LAN Ethernet y contiene la dirección IP del host de destino y la dirección MAC de multidifusión.",
      "Si un dispositivo que recibe una solicitud ARP tiene la dirección IPv4 de destino, responde con una respuesta ARP.",
      "Si ningún dispositivo responde a la solicitud ARP, el nodo de origen transmitirá el paquete de datos a todos los dispositivos del segmento de red.",
      "Cuando un host está encapsulando un paquete en una trama, se refiere a la tabla de direcciones MAC para determinar la asignación de direcciones IP a direcciones MAC."
    ],
    "correct": [
      0,
      2
    ]
  },
  {
    "question": "¿Cuál es una diferencia clave entre los datos capturados por NetFlow y los datos capturados por Wireshark?",
    "options": [
      "Los datos de NetFlow muestran contenido del flujo de red, mientras que los datos de Wireshark muestran estadísticas del flujo de red.",
      "NetFlow utiliza tcpdump para analizar los datos, mientras que Wireshark utiliza nfdump .",
      "NetFlow recopila metadatos de un flujo de red, mientras que Wireshark captura paquetes de datos completos.",
      "NetFlow proporciona datos de transacciones, mientras que Wireshark proporciona datos de sesiones."
    ],
    "correct": [
      2
    ]
  },
  {
    "question": "¿Qué herramienta captura paquetes de datos completos con una interfaz de línea de comandos solamente?",
    "options": [
      "Wireshark",
      "NBAR2",
      "tcpdump",
      "nfdump"
    ],
    "correct": [
      2
    ]
  },
  {
    "question": "Un usuario llama para reportar que una computadora no puede acceder a internet. El técnico de red pide al usuario que ejecute el comando ping 127.0.0.1 en una ventana de Símbolo del sistema (Command prompt). El usuario informa que el resultado es cuatro respuestas positivas. ¿Qué conclusión se puede extraer basándose en esta prueba de conectividad?",
    "options": [
      "La computadora puede acceder a la red.",
      "El problema existe más allá de la red local.",
      "La dirección IP obtenida del servidor DHCP es correcta.",
      "La implementación TCP/IP es funcional.",
      "La computadora puede acceder a internet. Sin embargo, es posible que el web browser (navegador web) no funcione."
    ],
    "correct": [
      3
    ]
  },
  {
    "question": "¿Qué tres campos del encabezado IPv4 no están en un encabezado IPv6? (Elija tres opciones).",
    "options": [
      "Desplazamiento de fragmentos",
      "Identificación",
      "Señalización",
      "Versión",
      "TTL",
      "Protocolo"
    ],
    "correct": [
      0,
      1,
      2
    ]
  },
  {
    "question": "¿Qué formato de PDU se utiliza cuando la NIC de un host recibe bits del medio de red?",
    "options": [
      "Trama",
      "Paquete",
      "Archivo",
      "Segmento"
    ],
    "correct": [
      0
    ]
  },
  {
    "question": "Un usuario está ejecutando el comando tracert a un dispositivo remoto. ¿En qué momento dejaría de reenviar el paquete un router que se encuentra en la ruta hacia el dispositivo de destino?",
    "options": [
      "Cuando los valores de los mensajes de solicitud de eco y de respuesta de eco llegan a cero",
      "Cuando el valor de RTT llega a cero",
      "Cuando el host responde con un mensaje de respuesta de eco ICMP",
      "Cuando el valor en el campo TTL llega a cero",
      "Cuando el router recibe un mensaje de ICMP de tiempo superado"
    ],
    "correct": [
      3
    ]
  },
  {
    "question": "¿Qué ataque a la red intenta crear un DoS para los clientes al evitar que obtengan un arrendamiento de DHCP?",
    "options": [
      "Ataque de tabla CAM",
      "Suplantación de dirección IP",
      "Suplantación de identidad de DHCP",
      "Inanición DHCP"
    ],
    "correct": [
      3
    ]
  },
  {
    "question": "Consulte la ilustración. Si el Host1 transfiriera un archivo al servidor, ¿qué capas del modelo TCP/IP se utilizarían?",
    "imageURL": "images/imagen01.jpg",
    "options": [
      "Solo las capas de aplicación, de Internet y de acceso a la red",
      "Solo las capas de aplicación, de transporte, de Internet y de acceso a la red",
      "Solo las capas de aplicación, de sesión, de transporte, de red, de enlace de datos y física",
      "Solo las capas de aplicación, de transporte, de red, de enlace de datos y física",
      "Solo las capas de aplicación y de Internet",
      "Solo las capas de Internet y de acceso a la red"
    ],
    "correct": [
      1
    ]
  },
  {
    "question": "Una compañía tiene un servidor de archivos que comparte una carpeta con el nombre Pública. La política de seguridad de la red especifica que, en relación con la carpeta Pública, se asignen derechos de solo lectura a cualquier persona que puede iniciar sesión en el servidor y derechos de edición solo al grupo de administradores de la red. ¿Qué componente se aborda en la estructura de servicios de red de AAA?",
    "options": [
      "Autenticación",
      "Autorización",
      "Automatización",
      "Registro"
    ],
    "correct": [
      1
    ]
  },
  {
    "question": "Un administrador desea crear cuatro subredes a partir de la dirección de red 192.168.1.0/24. ¿Cuál es la dirección de red y la máscara de subred de la segunda subred utilizable?",
    "options": [
      "Subred 192.168.1.32 Máscara de subred 255.255.255.240",
      "Subred 192.168.1.8 Máscara de subred 255.255.255.224",
      "Subred 192.168.1.128 Máscara de subred 255.255.255.192",
      "Subred 192.168.1.64 Máscara de subred 255.255.255.192",
      "Subred 192.168.1.64 Máscara de subred 255.255.255.240"
    ],
    "correct": [
      3
    ]
  },
  {
    "question": "¿Cuáles son las tres tecnologías que se deberían incluir en un sistema de administración de información y eventos de seguridad de SOC? (Elija tres opciones).",
    "options": [
      "dispositivo de firewall",
      "monitoreo de la seguridad",
      "inteligencia de amenazas",
      "prevención de intrusiones",
      "Administración de registros",
      "Servicio proxy"
    ],
    "correct": [
      1,
      2,
      4
    ]
  },
  {
    "question": "¿Qué parte del URL http://www.cisco.com/index.html representa el dominio DNS de nivel superior?",
    "options": [
      ".com",
      "http",
      "www",
      "index"
    ],
    "correct": [
      0
    ]
  },
  {
    "question": "Una compañía recién creada tiene quince computadoras con Windows 10 que deben instalarse antes de que la compañía empiece a operar. ¿Cuál es la mejor práctica que debe implementar el técnico al configurar el firewall de Windows?",
    "options": [
      "El técnico debe habilitar el firewall de Windows para el tráfico entrante e instalar otro software de firewall para controlar el tráfico saliente.",
      "El técnico debe crear instrucciones para los usuarios corporativos sobre cómo utilizar la cuenta de administrador con el fin de permitir aplicaciones a través del firewall de Windows.",
      "El técnico debe eliminar todas las reglas de firewall predeterminadas y denegar, de manera selectiva, el tráfico que llega a la red de la compañía.",
      "Después de implementar un software de seguridad de terceros para la compañía, el técnico debe verificar que el firewall de Windows esté deshabilitado."
    ],
    "correct": [
      3
    ]
  },
  {
    "question": "Después de que una herramienta de monitoreo de seguridad identifica un adjunto con malware en la red, ¿qué beneficio aporta la realización de un análisis retrospectivo?",
    "options": [
      "Un análisis retrospectivo puede ser de ayuda para realizar un seguimiento del comportamiento del malware a partir del punto de identificación.",
      "Puede identificar cómo el malware ingresó originalmente en la red.",
      "Puede calcular la probabilidad de un incidente en el futuro.",
      "Puede determinar qué host de red resultó afectado en primer lugar."
    ],
    "correct": [
      0
    ]
  },
  {
    "question": "Un técnico de soporte advierte una mayor cantidad de llamadas relacionadas con el rendimiento de las computadoras ubicadas en la planta de fabricación. El técnico cree que los botnets causan el problema. ¿Cuáles de las siguientes son dos propósitos de los botnets? (Elija dos opciones).",
    "options": [
      "Grabar todas las pulsaciones de teclas",
      "Atacar a otras computadoras",
      "Retener acceso a una computadora o a archivos hasta que se haya pagado el dinero",
      "Obtener acceso a la parte restringida del sistema operativo",
      "Transmitir virus o correo electrónico no deseado en computadoras de la misma red"
    ],
    "correct": [
      1,
      4
    ]
  },
  {
    "question": "De las siguientes afirmaciones, seleccione dos que describan el uso de algoritmos asimétricos. (Elija dos opciones).",
    "options": [
      "Si se utiliza una clave pública para cifrar los datos, debe utilizarse una clave pública para descifrarlos.",
      "Si se utiliza una clave privada para cifrar los datos, debe utilizarse una clave pública para descifrarlos.",
      "Si se utiliza una clave privada para cifrar los datos, debe utilizarse una clave privada para descifrarlos.",
      "Si se utiliza una clave pública para cifrar los datos, debe utilizarse una clave privada para descifrarlos.",
      "Las claves públicas y privadas pueden utilizarse indistintamente."
    ],
    "correct": [
      1,
      3
    ]
  },
  {
    "question": "¿Qué campo en el encabezado TCP indica el estado del three-way handshake?",
    "options": [
      "checksum",
      "ventana",
      "control bits",
      "reservado"
    ],
    "correct": [
      2
    ]
  },
  {
    "question": "¿Cuáles de las siguientes son dos funciones que proporciona la capa de red? (Elija dos).",
    "options": [
      "Proporcionar conexiones de extremo a extremo dedicadas.",
      "Transportar datos entre los procesos que se ejecutan en los hosts de origen y destino.",
      "Proporcionar a los dispositivos finales un identificador de red único.",
      "Colocar datos en el medio de red.",
      "Dirigir los paquetes de datos a los hosts de destino en otras redes."
    ],
    "correct": [
      2,
      4
    ]
  },
  {
    "question": "¿Qué tres afirmaciones describen un mensaje de descubrimiento de DHCP? (Elija tres).",
    "options": [
      "Todos los hosts reciben el mensaje pero sólo responde un servidor de DHCP.",
      "Solamente el servidor de DHCP recibe el mensaje.",
      "La dirección IP de destino es 255.255.255.255.",
      "El mensaje proviene de un cliente que busca una dirección IP.",
      "El mensaje proviene de un servidor que ofrece una dirección IP.",
      "La dirección MAC de origen tiene 48 bits (FF-FF-FF-FF-FF-FF)."
    ],
    "correct": [
      0,
      2,
      3
    ]
  },
  {
    "question": "Un host configurado para utilizar DHCP envía un mensaje DHCPDISCOVER. ¿Cuáles son la dirección IP y la dirección MAC de destino en este mensaje?",
    "options": [
      "Dirección MAC de destino 48 bits de 1s (FF-FF-FF-FF-FF-FF) y dirección IP de destino 255.255.255.255.",
      "Dirección MAC de destino FF-FF-FF-FF-FF-FF y dirección IP de destino 127.0.0.1.",
      "Dirección MAC de destino FF-FF-FF-FF-FF-FF y dirección IP de destino 0.0.0.0.",
      "Dirección MAC de destino de 48 bits de 1s y dirección IP de destino 0.0.0.0."
    ],
    "correct": [
      0
    ]
  },
  {
    "question": "¿Cuáles son los dos métodos que puede utilizar una NIC inalámbrica para descubrir un AP? (Elija dos opciones).",
    "options": [
      "Recepción de una trama de señal de difusión",
      "Comienzo de un protocolo de enlace de tres vías",
      "Envío de una solicitud de ARP de difusión",
      "Transmisión de una solicitud de sondeo",
      "Envío de una trama de multidifusión"
    ],
    "correct": [
      0,
      3
    ]
  },
  {
    "question": "¿Qué dos mensajes ICMPv6 se utilizan durante el proceso de resolución de direcciones MAC Ethernet? (Escoja dos opciones.)",
    "options": [
      "router solicitation",
      "echo request",
      "neighbor solicitation",
      "anuncio de enrutador",
      "neighbor advertisement"
    ],
    "correct": [
      2,
      4
    ]
  },
  {
    "question": "Observe la ilustración. ¿Cual es la dirección IP se debe utilizar como puerta de enlace predeterminada del host H1?",
    "imageURL": "images/imagen02.jpg",
    "options": [
      "R1: G0/0",
      "R1: S0/0/0",
      "R2: S0/0/1",
      "R2: S0/0/0"
    ],
    "correct": [
      0
    ]
  },
  {
    "question": "¿Qué dos protocolos pueden utilizar los dispositivos en el proceso de solicitud que implica el envío de un correo electrónico? (Elija dos opciones).",
    "options": [
      "IMAP",
      "POP",
      "HTTP",
      "POP3",
      "SMTP",
      "DNS"
    ],
    "correct": [
      4,
      5
    ]
  },
  {
    "question": "¿Qué tipo de evidencia no puede comprobar un hecho de seguridad de RI por sí sola?",
    "options": [
      "Confirmatoria",
      "La mejor",
      "Rumores",
      "Indirecta"
    ],
    "correct": [
      3
    ]
  },
  {
    "question": "Consulte la ilustración. Los switches tienen una configuración predeterminada. El host A debe comunicarse con el host D, pero no tiene la dirección MAC de la puerta de enlace predeterminada. ¿Cuáles dispositivos de red recibirán la solicitud ARP que fue enviada por el host A?",
    "imageURL": "images/imagen03.jpg",
    "options": [
      "Solo el router R1",
      "Solo los hosts A, B, C y D",
      "Solo el host D",
      "Solo los hosts B y C, y el router R1",
      "Solo los hosts A, B y C",
      "Solo los hosts B y C"
    ],
    "correct": [
      3
    ]
  },
  {
    "question": "Cuando se establece el perfil de una red para una organización, ¿qué elemento describe el tiempo que transcurre entre el establecimiento de un flujo de datos y su finalización?",
    "options": [
      "Ancho de banda de la conexión a Internet",
      "Convergencia de protocolo de routing",
      "Rendimiento total",
      "Duración de la sesión"
    ],
    "correct": [3]
  },
  {
    "question": "¿Cuál de las siguientes máscaras de subred se representa con la notación de barra diagonal /20?",
    "options": [
      "255.255.255.248",
      "255.255.255.0",
      "255.255.240.0",
      "255.255.224.0",
      "255.255.255.192"
    ],
    "correct": [2]
  },
  {
    "question": "¿Qué dos medidas deben adoptarse durante la fase de preparación del ciclo de vida de respuesta ante los incidentes definido por NIST? (Elija dos opciones).",
    "options": [
      "Crear el CSIRT y capacitar a sus miembros.",
      "Adquirir e implementar las herramientas necesarias para investigar los incidentes.",
      "Detectar todos los incidentes que se produjeron.",
      "Analizar completamente el incidente.",
      "Reunirse con todas las partes involucradas para hablar sobre el incidente ocurrido."
    ],
    "correct": [0, 1]
  },
  {
    "question": "¿Cuáles son las dos tareas que puede realizar un servidor DNS local? Elija dos opciones.",
    "options": [
      "Asignar nombres a direcciones IP para los hosts internos.",
      "Permitir la transferencia de datos entre dos dispositivos de red.",
      "Recuperar mensajes de correo electrónico.",
      "Proporcionar direcciones IP a los hosts locales.",
      "Reenviar solicitudes de resolución de nombres entre servidores."
    ],
    "correct": [0, 4]
  },
  {
    "question": "¿Cuáles de los siguientes son dos problemas de red potenciales que pueden surgir del funcionamiento del protocolo ARP? (Elija dos).",
    "options": [
      "En redes grandes que tienen un ancho de banda bajo, varios broadcasts de ARP pueden causar retrasos en la comunicación de datos.",
      "Una gran cantidad de transmisiones de solicitud de ARP pueden provocar que la tabla de direcciones MAC del host se desborde e impedir que el host se comunique dentro de la red.",
      "Varias respuestas ARP provocan que la tabla de direcciones MAC del switch incluya entradas que coinciden con las direcciones MAC de los hosts que están conectados al puerto del switch pertinente.",
      "Los atacantes de la red podrían manipular las asignaciones de direcciones MAC e IP en mensajes ARP con el objetivo de interceptar el tráfico de la red.",
      "La configuración manual de asociaciones ARP estáticas puede facilitar el envenenamiento ARP o la suplantación de direcciones MAC."
    ],
    "correct": [0, 3]
  },
  {
    "question": "¿Cuál protocolo de la capa de aplicación se utiliza para permite a las aplicaciones de Microsoft el uso compartido de archivos y los servicios de impresión?",
    "options": [
      "HTTP",
      "DHCP",
      "SMB",
      "SMTP"
    ],
    "correct": [2]
  },
  {
    "question": "Consulte la ilustración. Un administrador intenta resolver problemas de conectividad entre la PC1 y la PC2 y, para lograrlo, utiliza el comando tracert en la PC1. Sobre la base del resultado que se muestra, ¿por dónde debería comenzar a resolver el problema el administrador?",
    "imageURL": "images/imagen04.jpg",
    "options": [
      "PC2",
      "SW2",
      "R2",
      "SW1",
      "R1"
    ],
    "correct": [4]
  },
  {
    "question": "¿Qué dos campos o características examina Ethernet para determinar si una trama recibida es pasada a la capa de enlace de datos o descartada por la NIC? (Escoja dos opciones).",
    "options": [
      "Dirección MAC de origen",
      "Secuencia de verificación de trama",
      "tamaño mínimo de trama",
      "CEF",
      "MDIX automático"
    ],
    "correct": [1, 2]
  },
  {
    "question": "En términos de NAT, ¿qué tipo de dirección se refiere a la dirección IPv4 enrutable globalmente de un host de destino en Internet?",
    "options": [
      "Global interna",
      "Local interna",
      "Local externa",
      "Global externa"
    ],
    "correct": [3]
  },
  {
    "question": "¿Cuál de estas afirmaciones sobre los protocolos de red es correcta?",
    "options": [
      "Los protocolos de red definen el tipo de hardware que se utiliza y la forma en que se monta en bastidores.",
      "Definen cómo se intercambian los mensajes entre el origen y el destino.",
      "Solo se requieren para el intercambio de mensajes entre dispositivos de redes remotas.",
      "Todos funcionan en la capa de acceso a la red de TCP/IP."
    ],
    "correct": [1]
  },
  {
    "question": "¿Qué protocolo o servicio utiliza UDP para una comunicación cliente a servidor y TCP para la comunicación servidor a servidor?",
    "options": [
      "HTTP",
      "SMTP",
      "FTP",
      "DNS"
    ],
    "correct": [3]
  },
  {
    "question": "Seleccione los dos tipos de ataques utilizados en resoluciones de DNS abiertas. (Elija dos opciones).",
    "options": [
      "Uso de recursos",
      "Amortiguación",
      "Fast flux",
      "Amplificación y reflexión",
      "Envenenamiento ARP"
    ],
    "correct": [0, 3]
  },
  {
    "question": "¿Cuáles son las tres funciones proporcionadas por el servicio de syslog? (Elija tres opciones.)",
    "options": [
      "Recopilar información de registro para el control y la solución de problemas.",
      "Especificar los destinos de los mensajes capturados.",
      "Sondear de forma periódica a los agentes para obtener datos.",
      "Proporcionar estadísticas sobre los paquetes que recorren un dispositivo Cisco.",
      "Seleccionar el tipo de información de registro que se captura.",
      "Ofrecer análisis de tráfico."
    ],
    "correct": [0, 1, 4]
  },
  {
    "question": "Un empleado conecta inalámbrica con la red de la empresa mediante un teléfono celular. El empleado luego configurar el teléfono celular para operar como un punto de acceso inalámbrico que permite que los nuevos empleados se conecten con la red de la empresa. ¿Qué mejor de amenazas por tipo de seguridad se describe esta situación?",
    "options": [
      "el agrietarse",
      "suplantación de identidad",
      "punto de acceso dudoso",
      "denegación de servicio"
    ],
    "correct": [2]
  },
  {
    "question": "¿Qué métrica en el Grupo de métricas base de CVSS se utiliza con un vector de ataque?",
    "options": [
      "La determinación de si la autoridad inicial cambia a una segunda autoridad durante el ataque",
      "La proximidad del actor de la amenaza a la vulnerabilidad",
      "La presencia o ausencia de la necesidad de interacción con el usuario para que el ataque tenga éxito",
      "La cantidad de componentes, software, hardware o redes fuera del control del atacante y que deben estar presentes para poder atacar una vulnerabilidad con éxito"
    ],
    "correct": [1]
  },
  {
    "question": "Un técnico nota que una aplicación no responde a los comandos y que la PC parece responder con lentitud cuando se abren aplicaciones. ¿Cuál es la mejor herramienta administrativa para forzar la liberación de recursos del sistema por parte de la aplicación que no responde?",
    "options": [
      "Agregar o quitar programas",
      "Administrador de tareas",
      "Visor de eventos",
      "Restaurar sistema"
    ],
    "correct": [1]
  },
  {
    "question": "¿Cuál es la mejor descripción de la dirección IPv4 de destino que utiliza la multidifusión?",
    "options": [
      "Una dirección de grupo que comparte los últimos 23 bits con la dirección IPv4 de origen",
      "Una dirección de 48 bits que está determinada por la cantidad de miembros del grupo de multidifusión",
      "Una dirección IP que es única para cada destino de un grupo",
      "Una única dirección IP de multidifusión que utilizan todos los destinos de un grupo"
    ],
    "correct": [3]
  },
  {
    "question": "¿Cuáles son las dos características del método SLAAC para la configuración de direcciones IPv6? (Escoja dos opciones.)",
    "options": [
      "Los clientes envían mensajes de anuncio de router a los routeres para solicitar direcciones IPv6.",
      "Este método con estado para adquirir una dirección IPv6 requiere al menos un servidor DHCPv6.",
      "El direccionamiento IPv6 se asigna dinámicamente a los clientes mediante el uso de ICMPv6.",
      "La puerta de enlace predeterminada de un cliente IPv6 en una LAN será la dirección local del vínculo de la interfaz del router conectada a la LAN.",
      "Los mensajes de solicitud de router son enviados por el router para ofrecer direcciones IPv6 a los clientes."
    ],
    "correct": [2, 3]
  },
  {
    "question": "Un administrador de red está configurando un servidor AAA para administrar la autenticación RADIUS. ¿Cuales dos características son incluidas en la autenticación RADIUS? (Escoja dos opciones.)",
    "options": [
      "Procesos separados de autenticación y autorización",
      "Un único proceso de autenticación y autorización",
      "Encriptación sólo para los datos",
      "Contraseñas ocultas durante la transmisión",
      "Encriptación para todas las comunicaciones"
    ],
    "correct": [1, 3]
  },
  {
    "question": "¿Cuáles son dos inconvenientes del uso del sistema HIPS? (Escoja dos opciones.)",
    "options": [
      "Las instalaciones HIPS son vulnerables a ataques de fragmentación o ataques «variable TTL».",
      "HIPS tiene dificultades para construir una imagen de red precisa o coordinar eventos que ocurren en toda la red.",
      "Si el flujo de tráfico de red está encriptado, HIPS no puede acceder a formularios no encriptados (unecrypted forms) del tráfico.",
      "Si se usa el sistema HIPS, el administrador de red debe verificar la compatibilidad con todos los diferentes sistemas operativos utilizados en la red.",
      "Con HIPS, el éxito o fracaso de un ataque no se puede determinar fácilmente."
    ],
    "correct": [1, 3]
  },
  {
    "question": "¿Por qué razón un administrador de red utilizaría la herramienta Nmap?",
    "options": [
      "Para detectar e identificar puertos abiertos.",
      "Para proteger las direcciones IP privadas de los hosts internos.",
      "Para identificar anomalías específicas de la red.",
      "Recopilar y analizar las alertas y los registros."
    ],
    "correct": [0]
  },
  {
    "question": "¿Cuáles son dos usos de una lista de control de acceso? (Elija dos opciones.)",
    "options": [
      "Las ACL ayudan al router a determinar la mejor ruta hacia un destino.",
      "La posbilidad de que las ACL estándar puedan restringir el acceso a aplicaciones y puertos específicos.",
      "Las ACL pueden controlar a qué áreas puede acceder un host en una red.",
      "Las ACL pueden permitir o denegar el tráfico según la dirección MAC que se origina en el router.",
      "Las ACL proporcionan un nivel básico de seguridad para el acceso a la red."
    ],
    "correct": [2, 4]
  },
  {
    "question": "¿Cuáles son dos técnicas de evasión que utilizan los hackers? (Elija dos opciones.)",
    "options": [
      "Reconocimiento",
      "Caballo de Troya",
      "Suplantación de identidad",
      "Pivoting",
      "Rootkit"
    ],
    "correct": [3, 4]
  },
  {
    "question": "¿Qué es un punto de acceso de prueba de la red?",
    "options": [
      "Una tecnología de Cisco que proporciona estadísticas sobre los paquetes que pasan por un router o switch de multicapa",
      "Una característica admitida en switches de Cisco que permite que el switch copie tramas y las reenvíe a un dispositivo de análisis",
      "Una tecnología que ofrece informes en tiempo real y análisis de largo plazo sobre eventos de seguridad",
      "Un dispositivo pasivo que reenvía todo el tráfico y los errores de la capa física a un dispositivo de análisis"
    ],
    "correct": [3]
  },
  {
    "question": "Cuando un usuario visita el sitio web de una tienda en línea que utiliza HTTPS, el navegador del usuario consulta a la CA para obtener una CRL. ¿Cuál es el propósito de esta consulta?",
    "options": [
      "Comprobar la validez del certificado digital",
      "Comprobar la longitud de la clave usada para el certificado digital",
      "Solicitar un certificado digital firmado automáticamente a la CA",
      "Negociar el mejor tipo de cifrado que se usará"
    ],
    "correct": [0]
  },
  {
    "question": "Una persona va a una cafetería por primera vez y quiere tener acceso inalámbrico a Internet con su computadora portátil. ¿Cuál es el primer paso que llevará a cabo el cliente inalámbrico para comunicarse a través de la red con un marco de administración de redes inalámbricas?",
    "options": [
      "Acordar la carga útil con el AP",
      "Autenticar el AP",
      "Detectar el AP",
      "Asociarse con el AP"
    ],
    "correct": [2]
  },
  {
    "question": "¿Por qué un administrador de red elegiría Linux como sistema operativo en el Centro de Operaciones de Seguridad (Security Operations Center, SOC)?",
    "options": [
      "Es más fácil de usar que otros sistemas operativos de servidor.",
      "Se crean más aplicaciones de red para este entorno.",
      "El administrador tiene control de las funciones específicas de seguridad, pero no de las aplicaciones estándar.",
      "Puede adquirirse sin costo alguno."
    ],
    "correct": [2]
  },
  {
    "question": "¿Cuál tipo de sistema de archivos se creó específicamente para medios de disco óptico?",
    "options": [
      "ext2",
      "HFS+",
      "CDFS",
      "ext3"
    ],
    "correct": [2]
  },
  {
    "question": "¿Qué es el escalamiento de privilegios?",
    "options": [
      "Se le otorgan derechos a una persona porque esta ha recibido una promoción.",
      "Un problema de seguridad ocurre cuando un funcionario corporativo de alto nivel demanda derechos en relación con sistemas o archivos que no debería tener.",
      "De manera predeterminada, todos reciben la totalidad de los derechos en relación con todo; cuando una persona hace un abuso de privilegios, estos se quitan.",
      "Las vulnerabilidades en los sistemas se aprovechan para otorgar niveles de privilegio más altos que el que una persona o algún proceso debería tener."
    ],
    "correct": [3]
  },
  {
    "question": "¿Qué paso del ciclo de vida de la administración de vulnerabilidades determina un perfil de riesgo base para eliminar riesgos en función de la criticidad de los recursos, de las amenazas a las vulnerabilidades y de la clasificación de los recursos?",
    "options": [
      "Detectar",
      "Verificar",
      "Evaluar",
      "Priorizar activos"
    ],
    "correct": [2]
  },
  {
    "question": "Para los sistemas de red, ¿qué sistema de gestión se ocupa del inventario y del control de las configuraciones de hardware y software?",
    "options": [
      "Administración de recursos",
      "Gestión de riesgos",
      "Administración de vulnerabilidades",
      "Administración de la configuración"
    ],
    "correct": [3]
  },
  {
    "question": "Señale los dos servicios que presta la herramienta NetFlow. (Elija dos opciones.)",
    "options": [
      "Monitoreo de redes",
      "Factura de red basada en el uso",
      "Configuración de la calidad de servicio",
      "Análisis de registros",
      "Monitoreo de lista de acceso"
    ],
    "correct": [0, 1]
  },
  {
    "question": "¿Cuál es un propósito de la implementación de redes VLAN en una red?",
    "options": [
      "Prevenir bucles en la capa 2.",
      "Eliminar colisiones de red.",
      "Separar el tráfico de usuario.",
      "Permitir que los switches reenvíen paquetes de capa 3 sin un router."
    ],
    "correct": [2]
  },
  {
    "question": "El actor de una amenaza ha identificado la potencial vulnerabilidad del servidor web de una organización y está diseñando un ataque. ¿Qué es lo que posiblemente hará el actor de la amenaza para construir un arma de ataque?",
    "options": [
      "Crear un punto de persistencia mediante la adición de servicios.",
      "Recopilar las credenciales de los desarrolladores y administradores del servidor web.",
      "Obtener una herramienta automatizada para aplicar la carga útil de malware a través de la vulnerabilidad.",
      "Instalar un shell web en el servidor web para un acceso persistente."
    ],
    "correct": [2]
  },
  {
    "question": "Consulte la ilustración. Un analista especializado en ciberseguridad está utilizando Sguil para comprobar las alertas de seguridad. ¿Cómo está ordenada la vista actual?",
    "imageURL": "images/imagen05.jpg",
    "options": [
      "Por fecha y hora",
      "Por número de sensor",
      "Por IP de origen",
      "Por frecuencia"
    ],
    "correct": [3]
  },
  {
    "question": "¿Cuáles son las tres funciones principales de Security Onion? (Elija tres opciones.)",
    "options": [
      "Contención de amenazas",
      "Planificación de continuidad de los negocios",
      "Análisis de alertas",
      "Captura de paquete completo",
      "Administración de dispositivos móviles",
      "Detección de intrusiones"
    ],
    "correct": [2, 3, 5]
  },
  {
    "question": "¿Qué tres procedimientos ofrece Sguil a los analistas especializados en seguridad para ocuparse de las alertas? (Elija tres opciones.)",
    "options": [
      "Escalar una alerta dudosa.",
      "Usar otras herramientas y fuentes de información.",
      "Crear consultas con Query Builder.",
      "Fijar la caducidad de los falsos positivos.",
      "Correlacionar alertas similares en una sola línea.",
      "Clasificar los positivos verdaderos."
    ],
    "correct": [0, 3, 5]
  },
  {
    "question": "¿Cuáles son los dos escenarios en los que el análisis probabilístico de seguridad es el más adecuado? (Escoja dos opciones.)",
    "options": [
      "Cuando variables aleatorias crean dificultades para conocer el resultado (o las consecuencias) de cualquier evento con certeza",
      "Cuando se analizan eventos con la suposición de que estos siguen pasos predefinidos",
      "Cuando aplicaciones que cumplen los estándares de aplicación/red son analizadas",
      "Cuando se analizan aplicaciones diseñadas para evitar Firewalls",
      "Cuando cada evento es el resultado inevitable de causas anteriores"
    ],
    "correct": [0, 1]
  },
  {
    "question": "¿De qué dos maneras ICMP puede ser una amenaza de seguridad para una compañía? (Elija dos opciones.)",
    "options": [
      "Al dañar paquetes de datos IP de red",
      "Al proporcionar una conducto para ataques DoS",
      "Al dañar datos entre servidores de correo electrónico y destinatarios de correo electrónico",
      "Al infiltrar páginas web",
      "Al recopilar información sobre una red"
    ],
    "correct": [1, 4]
  },
  {
    "question": "Si un centro de operaciones de seguridad (Security Operations Center SOC) tiene un objetivo de tiempo de actividad del 99,999%, ¿cuántos minutos de tiempo de inactividad al año se considerarían dentro de su objetivo?",
    "options": [
      "Aproximadamente 5 minutos por año.",
      "Aproximadamente 30 minutos por año.",
      "Aproximadamente 20 minutos por año.",
      "Aproximadamente 10 minutos por año."
    ],
    "correct": [0]
  },
  {
    "question": "¿Qué caracteriza a un atacante?",
    "options": [
      "Todos ellos son individuos altamente calificados.",
      "Siempre tratan de causar algún daño a una persona u organización.",
      "Todos pertenecen al crimen organizado.",
      "Siempre usan herramientas avanzadas para lanzar ataques."
    ],
    "correct": [1]
  },
  {
    "question": "¿Cuál es una propiedad de la tabla ARP en un dispositivo?",
    "options": [
      "Las entradas de una tabla ARP tienen una marca de tiempo y se purgan después de que expire el tiempo de espera.",
      "Los sistemas operativos Windows almacenan entradas de caché ARP durante 3 minutos.",
      "Cada sistema operativo utiliza el mismo temporizador para eliminar entradas antiguas de la caché ARP.",
      "Las entradas de direcciones IP a Mac estáticas se eliminan de manera dinámica de la tabla ARP."
    ],
    "correct": [0]
  },
  {
    "question": "¿Qué técnica es utilizada en ataques de ingeniería social?",
    "options": [
      "Hombre-en-el-medio (Man-in-the-middle)",
      "Suplantación de identidad (Phising)",
      "Envío de correo no deseado",
      "Desbordamiento de búfer"
    ],
    "correct": [1]
  },
  {
    "question": "¿Qué herramienta de seguridad de depuración puede ser utilizada por los hackers de sombrero negro con el fin de aplicar ingeniería inversa en archivos binarios cuando programan ataques?",
    "options": [
      "AIDE",
      "Firesheep",
      "Skipfish",
      "WindDbg"
    ],
    "correct": [3]
  },
  {
    "question": "¿Cuál es una característica de CybOX?",
    "options": [
      "Permite el intercambio en tiempo real de los indicadores de ciberamenazas entre el gobierno federal de Estados Unidos y el sector privado.",
      "Es un conjunto de especificaciones para intercambiar información sobre ciberamenazas entre organizaciones.",
      "Es la especificación correspondiente a un protocolo de la capa de aplicación que permite la comunicación de CTI por HTTPS.",
      "Es un conjunto de esquemas estandarizados para especificar, capturar, caracterizar y comunicar eventos y propiedades de operaciones de red."
    ],
    "correct": [3]
  },
  {
    "question": "¿Cuál es el objetivo principal de una plataforma de inteligencia contra amenazas (TIP)?",
    "options": [
      "Agregar los datos en un solo lugar y presentarlos en un formato comprensible y utilizable",
      "Proporcionar una plataforma de operaciones de seguridad que integre y mejore diversas herramientas de seguridad e inteligencia de amenazas",
      "Proporcionar una especificación a un protocolo de la capa de aplicación que permite la comunicación de CTI por HTTPS",
      "Proporcionar un esquema estandarizado para especificar, capturar, caracterizar y comunicar eventos y propiedades de operaciones de red"
    ],
    "correct": [0]
  },
  {
    "question": "Un administrador descubre que un usuario está accediendo a un sitio web recientemente establecido que puede ser perjudicial para la seguridad de la empresa. ¿Qué acción debe tomar el administrador en primer lugar en términos de la política de seguridad?",
    "options": [
      "Suspender inmediatamente los privilegios de red del usuario.",
      "Solicitar al usuario que pare inmediatamente e informe al usuario que ello constituye motivo de despido.",
      "Crear una regla de firewall que bloquee el sitio web respectivo.",
      "Revisar la AUP inmediatamente y hacer que todos los usuarios firmen la AUP actualizada."
    ],
    "correct": [3]
  },
  {
    "question": "Un técnico trabaja en la resolución de un problema de conectividad de red. Los pings que se hacen al router inalámbrico se realizan correctamente, pero los que se hacen a un servidor en Internet no son exitosos. ¿Qué comando de CLI puede ayudar al técnico a encontrar la ubicación del problema de networking?",
    "options": [
      "ipconfig/renew",
      "msconfig",
      "tracert",
      "ipconfig"
    ],
    "correct": [2]
  },
  {
    "question": "Consulte la ilustración. ¿Qué solución puede proporcionar una VPN entre el sitio A y el sitio B que admita el encapsulamiento de cualquier protocolo de capa 3 entre las redes internas de cada sitio?",
    "imageURL": "images/imagen06.jpg",
    "options": [
      "Un túnel GRE",
      "Un túnel IPSec",
      "Un túnel de acceso remoto",
      "VPN con SSL de Cisco"
    ],
    "correct": [0]
  },
  {
    "question": "¿Qué dos funciones están incluidas en los protocolos TACACS+ y RADIUS? (Elija dos opciones.)",
    "options": [
      "Utilización de protocolos de capa de transporte",
      "Procesos de autenticación y de autorización separados",
      "Compatibilidad con 802.1X",
      "Encriptación de contraseñas",
      "Compatibilidad con SIP"
    ],
    "correct": [0, 3]
  },
  {
    "question": "¿Cuál de las siguientes es una diferencia entre el modelo de red de cliente/servidor y el modelo de red entre pares?",
    "options": [
      "Cada dispositivo de una red entre pares puede funcionar como cliente o como servidor.",
      "Una transferencia de datos que utiliza un dispositivo que funciona como cliente requiere que haya presente un servidor exclusivo.",
      "La transferencia de archivos solamente se puede realizar en el modelo de cliente/servidor.",
      "Una red entre pares transfiere datos más rápido que una red de cliente/servidor."
    ],
    "correct": [0]
  },
  {
    "question": "¿Cuáles de las siguientes son dos características de las direcciones MAC Ethernet? Elija dos opciones.",
    "options": [
      "Se expresan como 12 dígitos hexadecimales.",
      "Son enrutables en Internet.",
      "Son globalmente únicas.",
      "Utilizan una estructura jerárquica flexible.",
      "Deben ser únicas tanto para las interfaces Ethernet como para las interfaces seriales en un dispositivo."
    ],
    "correct": [0, 2]
  },
  {
    "question": "Una computadora presenta a un usuario una pantalla en la que se solicita el pago antes de que los datos del usuario sean accesibles para el mismo usuario. ¿Qué tipo de malware es este?",
    "options": [
      "un tipo de gusano",
      "un tipo de bomba lógica",
      "un tipo de ransomware",
      "un tipo de virus"
    ],
    "correct": [2]
  },
  {
    "question": "¿Qué tipo de ataque está dirigido a una base de datos de SQL mediante el campo de entrada de un usuario?",
    "options": [
      "Inyección SQL",
      "Scripts entre sitios",
      "Desbordamiento del búfer",
      "Inyección XML"
    ],
    "correct": [0]
  },
  {
    "question": "De las siguientes opciones, ¿cuáles son dos métodos para mantener el estado de revocación de certificado? (Elija dos opciones.)",
    "options": [
      "LDAP",
      "CA subordinada",
      "CRL",
      "DNS",
      "OCSP"
    ],
    "correct": [2, 4]
  },
  {
    "question": "¿Qué dos comandos net están asociados con el uso compartido de recursos de red? (Elija dos opciones.)",
    "options": [
      "net accounts",
      "net start",
      "net use",
      "net stop",
      "net share"
    ],
    "correct": [2, 4]
  },
  {
    "question": "¿Qué dispositivo en un enfoque de defensa en profundidad con varias capas niega las conexiones iniciadas de redes no confiables a redes internas, pero permite a los usuarios internos de una organización conectarse a redes no confiables?",
    "options": [
      "Router interno",
      "Switch de capa de acceso",
      "IPS",
      "Firewall"
    ],
    "correct": [3]
  },
  {
    "question": "¿Cuál de las siguientes opciones describe mejor la amenaza a la seguridad denominada “suplantación de identidad (spoofing)”? ",
    "options": [
      "Intercepta el tráfico entre dos hosts o inserta información falsa en el tráfico entre dos hosts.",
      "Simula que los datos provienen de un origen que no es el verdadero.",
      "Envía correo electrónico masivo a personas, listas o dominios con la intención de evitar que los usuarios tengan acceso al correo electrónico.",
      "Envía datos en cantidades anormalmente grandes a un servidor remoto para evitar el acceso del usuario a los servicios del servidor."
    ],
    "correct": [1]
  },
  {
    "question": "¿Cuáles son dos propiedades de una función hash criptográfica? (Elija dos opciones.)",
    "options": [
      "La salida tiene una longitud fija.",
      "Las funciones hash pueden duplicarse con fines de autenticación.",
      "Las entradas complejas producirán algoritmos hash complejos.",
      "La entrada de un algoritmo hash determinado debe tener un tamaño fijo.",
      "La función hash es unidireccional e irreversible."
    ],
    "correct": [0, 4]
  },
  {
    "question": "¿Qué dos puntos garantizan las firmas digitales sobre código que se descarga de Internet? (Elija dos opciones.)",
    "options": [
      "El código no se ha modificado desde que salió del editor de software.",
      "El código es auténtico y realmente es provisto por el editor.",
      "El código no contiene ningún virus.",
      "El código no contiene errores.",
      "El código se cifró con una clave pública y una clave privada."
    ],
    "correct": [0, 1]
  },
  {
    "question": "Un usuario abre tres navegadores en la misma PC para acceder a www.cisco.com con el objetivo de buscar información sobre el curso de certificación. El servidor web de Cisco envía un datagrama como respuesta a la solicitud desde uno de los navegadores web. ¿Qué información utiliza la pila de protocolos TCP/IP en la PC para identificar el navegador web de destino?",
    "options": [
      "El número de puerto de origen",
      "La dirección IP de origen",
      "La dirección IP de destino",
      "El número de puerto de destino"
    ],
    "correct": [3]
  },
  {
    "question": "¿Qué parámetro inalámbrico utiliza un punto de acceso para transmitir tramas que incluyen el SSID?",
    "options": [
      "Modo activo",
      "Configuración de los canales",
      "Modo de seguridad",
      "Modo pasivo"
    ],
    "correct": [3]
  },
  {
    "question": "¿Qué firewall ejecutado en un host utiliza un enfoque de tres perfiles para configurar la funcionalidad de firewall?",
    "options": [
      "iptables",
      "Firewall de Windows",
      "nftables",
      "TCP Wrapper"
    ],
    "correct": [1]
  },
  {
    "question": "¿Cuál paso en el ciclo de gestión de vulnerabilidades (Vulnerability Management Life Cycle VMLC) categoriza los activos en grupos o unidades comerciales (business units), y les asigna un valor comercial a los grupos de activos basándose en qué tan críticos son para las operaciones comerciales?",
    "options": [
      "Reportar",
      "Priorizar recursos (activos)",
      "Remediar",
      "Evaluar"
    ],
    "correct": [1]
  },
  {
    "question": "¿Cómo pueden los datos estadísticos utilizarse para describir o predecir el comportamiento de la red?",
    "options": [
      "Mostrando mensajes de alerta generados por Snort",
      "Grabando conversaciones entre los terminales de la red",
      "Haciendo una lista de los resultados de las actividades de navegación web de los usuarios",
      "Comparando el comportamiento normal de la red con el comportamiento actual de la red"
    ],
    "correct": [3]
  },
  {
    "question": "¿Qué término se utiliza para describir consultas automatizadas que son útiles para que el flujo de trabajo de ciberoperaciones sea más eficaz?",
    "options": [
      "Cuaderno de estrategias",
      "Rootkit",
      "Cadena de eliminación cibernética",
      "Cadena de custodia"
    ],
    "correct": [0]
  },
  {
    "question": "¿Qué tipo de mensaje ICMPv6 proporciona información de direccionamiento de red a los hosts que utilizan SLAAC?",
    "options": [
      "Solicitud de router",
      "Solicitud de vecino",
      "Oferta (o anuncio) de router",
      "Oferta (o anuncio) de vecino"
    ],
    "correct": [2]
  },
  {
    "question": "¿Qué dos tipos de datos se clasificarían como información de identificación personal (PII)? (Elija dos opciones.)",
    "options": [
      "Lectura del termostato del hogar",
      "Cantidad promedio de ganado vacuno por región",
      "Número de identificación del vehículo",
      "Fotografías de Facebook",
      "Uso de la emergencia hospitalaria por estado"
    ],
    "correct": [2, 3]
  },
  {
    "question": "Un técnico necesita verificar los permisos de archivo en un archivo de Linux específico. ¿Qué comando utilizaría el técnico?",
    "options": [
      "sudo",
      "vi",
      "ls -l",
      "cd"
    ],
    "correct": [2]
  },
  {
    "question": "¿Para qué tres herramientas de seguridad mantiene Cisco Talos un conjunto de reglas de detección de incidentes de seguridad? (Escoja tres opciones.)",
    "options": [
      "Socat",
      "NetStumbler",
      "Snort",
      "ClamAV",
      "SpamCop"
    ],
    "correct": [2, 3, 4]
  },
  {
    "question": "En un sistema operativo Linux, ¿qué componente interpreta los comandos de usuario e intenta ejecutarlos?",
    "options": [
      "GUI",
      "Shell",
      "Kernel",
      "daemon"
    ],
    "correct": [1]
  },
  {
    "question": "Cuando las ACL están configuradas para bloquear la suplantación de direcciones IP y los ataques de inundación DoS, ¿qué mensaje ICMP debe permitirse tanto entrante como saliente?",
    "options": [
      "Echo reply",
      "Unreachable",
      "Echo",
      "Source quench"
    ],
    "correct": [2]
  },
  {
    "question": "¿Qué componente central de código abierto de Elastic Stack es responsable de aceptar los datos en su formato nativo y hacer que los elementos de los datos sean coherentes en todas las fuentes?",
    "options": [
      "Elasticsearch",
      "Beats",
      "Kibana",
      "Logstash"
    ],
    "correct": [3]
  },
  {
    "question": "¿Cuáles son tres objetivos de un ataque de escaneo de puertos (port scan)? (Elija tres opciones.)",
    "options": [
      "Identificar servicios activos",
      "Identificar configuraciones periféricas",
      "Deshabilitar puertos y servicios usados",
      "Determinar posibles vulnerabilidades",
      "Descubrir contraseñas del sistema",
      "Identificar sistemas operativos"
    ],
    "correct": [0, 3, 5]
  },
  {
    "question": "¿Qué medida puede tomar un analista de seguridad para realizar una monitoreo de seguridad eficaz frente a tráfico de red encriptado por tecnología SSL?",
    "options": [
      "Implementar un Cisco ASA.",
      "Utilizar un servidor Syslog para capturar tráfico de red.",
      "Requerir conexiones de acceso remoto a través de IPsec VPN.",
      "Implementar un Cisco SSL Appliance."
    ],
    "correct": [3]
  },
  {
    "question": "¿Qué sistema de administración implementa sistemas que realizan un seguimiento de la ubicación y la configuración de software y dispositivos en red en toda una empresa?",
    "options": [
      "Administración de vulnerabilidades",
      "Administración de recursos",
      "Gestión de riesgos",
      "Administración de la configuración"
    ],
    "correct": [1]
  },
  {
    "question": "¿Qué registro del Visor de eventos de Windows incluye eventos relativos al funcionamiento de los controladores, los procesos y el hardware?",
    "options": [
      "Archivos de registro de aplicaciones",
      "Archivos de registro de seguridad",
      "Archivos de registro del sistema",
      "Archivos de registro de configuración"
    ],
    "correct": [2]
  },
  {
    "question": "¿Qué tipo de evento se registra en dispositivos con IPS de última generación (NGIPS) de Cisco mediante el uso de FirePOWER services cuando se detectan cambios en la red monitoreada?",
    "options": [
      "Descubrimiento de red",
      "host o terminal",
      "Intrusión",
      "Conexión"
    ],
    "correct": [0]
  },
  {
    "question": "Una pieza de malware obtuvo acceso a una estación de trabajo y emitió una consulta de búsqueda de DNS a un servidor de CnC. ¿Cuál es el propósito de este ataque?",
    "options": [
      "Enmascarar la dirección IP de la estación de trabajo",
      "Solicitar un cambio de la dirección IP",
      "Comprobar el nombre de dominio de la estación de trabajo",
      "Enviar datos confidenciales robados con codificación"
    ],
    "correct": [3]
  },
  {
    "question": "Cuando ocurre un ataque de seguridad, ¿qué dos enfoques deben adoptar los profesionales de seguridad para mitigar un sistema comprometido durante el paso «Acciones en objetivos» según lo define el modelo de eliminación cibernética? (Elija dos opciones.)",
    "options": [
      "Capacitar a los desarrolladores web sobre cómo asegurar códigos.",
      "Detectar exfiltración de datos, movimiento lateral y uso no autorizado de credenciales.",
      "Reunir archivos y metadatos de malware para análisis futuros.",
      "Desarrollar detecciones para el comportamiento de malware conocido.",
      "Realizar análisis forense de terminales para una priorización rápida de las medidas por tomar."
    ],
    "correct": [1, 4]
  },
  {
    "question": "Según el NIST, ¿qué paso en el proceso de análisis forense digital consiste en preparar y presentar información obtenida mediante el análisis minucioso de los datos?",
    "options": [
      "Recopilación",
      "Análisis",
      "Examen",
      "Elaboración de informes"
    ],
    "correct": [3]
  },
  {
    "question": "¿Qué dos tipos de tráfico de red que no se puede leer podrían eliminarse de los datos recogidos por NSM? (Elija dos opciones.)",
    "options": [
      "Tráfico STP",
      "Tráfico IPsec",
      "Tráfico SSL",
      "Tráfico de actualizaciones de routing",
      "Tráfico de difusión"
    ],
    "correct": [1, 2]
  },
  {
    "question": "Se ha asignado la dirección IPv6 2001:0db8:cafe:4500:1000:00d8:0058:00ab/64 a un dispositivo. ¿Cuál es el identificador de red del dispositivo?",
    "options": [
      "2001:0db8:cafe:4500:1000:00d8:0058:00ab",
      "2001:0db8:cafe:4500:1000",
      "1000:00d8:0058:00ab",
      "2001:0db8:cafe:4500",
      "2001"
    ],
    "correct": [3]
  },
  {
    "question": "¿Qué información es requerida para una consulta WHOIS?",
    "options": [
      "FQDN del dominio",
      "Dirección global externa del cliente",
      "Dirección local del vínculo del propietario del dominio",
      "Dirección del servidor de búsqueda de ICANN"
    ],
    "correct": [0]
  },
  {
    "question": "Un analista de ciberseguridad necesita recopilar datos de alerta. ¿Cuáles son tres herramientas de detección para realizar esta tarea en la arquitectura Security Onion? (Escoja tres opciones.)",
    "options": [
      "Kibana",
      "Zeek",
      "CapME",
      "Wazuh",
      "Wireshark",
      "Sguil"
    ],
    "correct": [1, 3, 4]
  },
  {
    "question": "Un administrador está tratando de desarrollar una política de seguridad BYOD para los empleados que están trayendo una amplia cantidad de dispositivos para conectarlos a la red de la empresa. ¿Cuáles tres objetivos debe abordar la política de seguridad del BYOD? (Escoja tres opciones.)",
    "options": [
      "Todos los dispositivos deben tener autenticación abierta con la red corporativa.",
      "Deben definirse los derechos y las actividades permitidas en la red corporativa.",
      "Todos los dispositivos deben estar asegurados contra responsabilidad si se utilizan para comprometer la red corporativa.",
      "Se debe permitir que todos los dispositivos se conecten a la red corporativa sin problemas.",
      "Deben establecerse salvaguardias para cualquier dispositivo personal que pueda ser comprometido.",
      "Se debe definir el nivel de acceso de los empleados al conectarse a la red corporativa."
    ],
    "correct": [1, 4, 5]
  },
  {
    "question": "¿Qué término describe un conjunto de herramientas de software diseñadas para aumentar los privilegios de un usuario o para otorgarle acceso al usuario a porciones del sistema operativo a las que normalmente no se debería poder acceder?",
    "options": [
      "Administrador de paquetes",
      "Compilador",
      "Rootkit",
      "Pruebas de penetración"
    ],
    "correct": [2]
  },
  {
    "question": "¿Qué método se utiliza para que los usuarios no autorizados no puedan leer los datos?",
    "options": [
      "Cifrar los datos.",
      "Agregar una suma de comprobación al final de los datos.",
      "Fragmentar los datos.",
      "Asignar un nombre de usuario y una contraseña."
    ],
    "correct": [0]
  },
  {
    "question": "¿Qué herramienta puede utilizarse en un sistema Cisco AVC para analizar los datos de análisis de la aplicación y presentarlos en los informes del panel?",
    "options": [
      "NBAR2",
      "Prime",
      "IPFIX",
      "NetFlow"
    ],
    "correct": [1]
  },
  {
    "question": "¿Cuál es el resultado de la utilización de dispositivos de seguridad que incluyen servicios de descifrado e inspección de HTTPS?",
    "options": [
      "Los contratos de servicio mensuales con sitios de filtrado web de buena reputación pueden ser costosos.",
      "Los dispositivos deben tener nombres de usuario y contraseñas preconfigurados para todos los usuarios.",
      "Los dispositivos introducen demoras de procesamiento y cuestiones de privacidad.",
      "Los dispositivos requieren monitoreo y puesta a punto continuos."
    ],
    "correct": [2]
  },
  {
    "question": "En el ciclo de vida del proceso de respuesta ante los incidentes de NIST, ¿qué tipo de vector de ataque implica el uso de la fuerza bruta contra los dispositivos, las redes o los servicios?",
    "options": [
      "Pérdida o robo",
      "Medios",
      "Suplantación de identidad",
      "Desgaste"
    ],
    "correct": [3]
  },
  {
    "question": "Consulte la ilustración. Un analista especializado en ciberseguridad está viendo paquetes que se reenviaron al switch S2. ¿Qué direcciones identificarán tramas que contienen los datos enviados de la PCA a la PCB?",
    "imageURL": "images/imagen07.jpg",
    "options": [
      "Src IP: 192.168.1.212\nSrc MAC: 00-60-0F-B1-33-33\nDst IP: 192.168.2.101\nDst MAC: 00-D0-D3-BE-00-00",
      "Src IP: 192.168.2.1\nSrc MAC: 00-60-0F-B1-33-33\nDst IP: 192.168.2.101\nDst MAC: 08-CB-8A-5C-BB-BB",
      "Src IP: 192.168.1.212\nSrc MAC: 00-60-0F-B1-33-33\nDst IP: 192.168.2.101\nDst MAC: 08-CB-8A-5C-BB-BB",
      "Src IP: 192.168.1.212\nSrc MAC: 01-90-C0-E4-AA-AA\nDst IP: 192.168.2.101\nDst MAC: 08-CB-8A-5C-BB-BB"
    ],
    "correct": [0]
  },
  {
    "question": "¿Cuáles dos técnicas se utilizan en un ataque smurf (pitufo)? (Escoja dos opciones.)",
    "options": [
      "Agotamiento de recursos",
      "Reflexión",
      "Amplificación",
      "Botnets",
      "Secuestro de sesiones (session hijacking)"
    ],
    "correct": [1, 2]
  },
  {
    "question": "El servidor HTTP ha respondido a una solicitud de cliente con un código de estado 200. ¿Qué indica este código de estado?",
    "options": [
      "El servidor no pudo encontrar el recurso solicitado, posiblemente debido a una dirección URL incorrecta.",
      "La solicitud ha sido aceptada para su procesamiento, pero el procesamiento no está terminado.",
      "El servidor entiende la solicitud, pero el recurso no se cumplirá.",
      "La solicitud se completó de manera correcta."
    ],
    "correct": [3]
  },
  {
    "question": "¿Qué termino se utiliza para describir al proceso de identificar los datos relacionados con los NSM que se recopilan?",
    "options": [
      "Archivado de datos (data archiving)",
      "Reducción de datos (data reduction)",
      "Normalización de datos (data normalization)",
      "Retención de datos (data retention)"
    ],
    "correct": [2]
  },
  {
    "question": "¿Qué herramienta incluida en Security Onion es una serie de plugins de software que envía distintos tipos de datos hacia los almacenes de datos de Elasticsearch?",
    "options": [
      "OSSEC",
      "ElastAlert",
      "Curator",
      "Beats"
    ],
    "correct": [3]
  },
  {
    "question": "¿Qué herramienta es una aplicación web que provee al analista de ciberseguridad una forma fácil de leer y visualizar una sesión completa de capa 4?",
    "options": [
      "OSSEC",
      "Zeek",
      "CapME",
      "Snort"
    ],
    "correct": [2]
  },
  {
    "question": "¿Cuáles son las tres direcciones IP que se consideran direcciones privadas? (Elija tres opciones.)",
    "options": [
      "198.168.6.18",
      "172.68.83.35",
      "192.168.5.29",
      "172.17.254.4",
      "10.234.2.1",
      "128.37.255.6"
    ],
    "correct": [2, 3, 4]
  },
  {
    "question": "En las evaluaciones de la seguridad de la red, ¿que tipo de prueba se utiliza para evaluar el riesgo que suponen las vulnerabilidades para una organización específica, incluida la evaluación de la probabilidad de ataques y del impacto de los ataques exitosos en la organización?",
    "options": [
      "Análisis de riesgos",
      "Pruebas de penetración",
      "Escaneo de puertos",
      "Evaluación de vulnerabilidades"
    ],
    "correct": [0]
  },
  {
    "question": "Al abordar un riesgo identificado, ¿cuál estrategia tiene como objetivo trasladar parte del riesgo a otras partes?",
    "options": [
      "riesgo compartido",
      "retención de riesgos",
      "reducción de riesgos",
      "evasión de riesgos"
    ],
    "correct": [0]
  },
  {
    "question": "¿Qué termino se usa para describir evidencia que se encuentra en su estado original?",
    "options": [
      "Evidencia directa",
      "Evidencia que lo corrobora",
      "La mejor evidencia",
      "Evidencia indirecta"
    ],
    "correct": [2]
  },
  {
    "question": "Un dispositivo cliente inició una solicitud HTTP segura a un navegador web. ¿Qué número de dirección de puerto conocido se asocia con la dirección de destino?",
    "options": [
      "110",
      "404",
      "443",
      "80"
    ],
    "correct": [2]
  },
  {
    "question": "¿Cuáles son tres características de un sistema de gestión de la seguridad de la información? (Escoja tres opciones.)",
    "options": [
      "Se basa en la aplicación de servidores y dispositivos de seguridad.",
      "Toma el control del inventario y el control de configuraciones de hardware y software.",
      "Consiste en un conjunto de prácticas que una organización aplica sistemáticamente para asegurar la mejora continua en la seguridad de la información.",
      "Consiste en un marco de trabajo de gestión a través del cual una organización identifica, analiza y aborda los riesgos que corre la seguridad de la información.",
      "Involucra la implementación de sistemas que rastrean la ubicación y configuración de software y dispositivos en la red en una empresa.",
      "Es un enfoque de ciberseguridad sistemático con varias capas."
    ],
    "correct": [2, 3, 5]
  },
  {
    "question": "¿Cuál dispositivo admite el uso de SPAN para permitir la supervisión de actividades maliciosas?",
    "options": [
      "Cisco NAC",
      "Cisco Security Agent",
      "Cisco IronPort",
      "Cisco Catalyst switch"
    ],
    "correct": [3]
  },
  {
    "question": "¿Qué método se puede utilizar para fortalecer un dispositivo?",
    "options": [
      "Permitir que los servicios predeterminados permanezcan habilitados",
      "Utilizar SSH y deshabilitar el acceso a cuentas raíz a través de SSH",
      "Permitir la detección automática de USB",
      "Mantener el uso de las mismas contraseñas"
    ],
    "correct": [1]
  },
  {
    "question": "¿Qué tipo de dato se consideraría un ejemplo de dato volátil?",
    "options": [
      "Archivos de registro",
      "Archivos temporales",
      "Registros de la memoria",
      "Caché del navegador web"
    ],
    "correct": [2]
  },
  {
    "question": "¿Cuáles dos protocolos de red puede utilizar un atacante para exfiltrar (o extraer) datos mediante tráfico disfrazado como tráfico normal de red? (Escoja dos opciones.)",
    "options": [
      "DNS",
      "Syslog",
      "NTP",
      "SMTP",
      "HTTP"
    ],
    "correct": [0, 4]
  },
  {
    "question": "¿Cuál es una característica de un análisis probabilístico en una evaluación de alerta?",
    "options": [
      "Cada evento es el resultado inevitable de causas antecedentes",
      "Es un análisis de aplicaciones que cumplen los estándares de aplicación/red",
      "Son Métodos precisos que obtienen el mismo resultado al depender de condiciones predefinidas",
      "Son variables aleatorias que crean dificultades para conocer el resultado de cualquier evento con certeza"
    ],
    "correct": [3]
  },
  {
    "question": "Consulte la ilustración. ¿Qué campo en la ventana de evento Sguil indica la cantidad de veces que se detecta un evento para la misma dirección IP de origen y de destino?",
    "imageURL": "images/imagen08.png",
    "options": [
      "AlertID",
      "ST",
      "CNT",
      "Pr"
    ],
    "correct": [2]
  },
  {
    "question": "De las siguientes afirmaciones, seleccione dos que describan las características de algoritmos asimétricos. (Elija dos opciones.)",
    "options": [
      "Normalmente se implementan en los protocolos SSL y SSH.",
      "Proporcionan confidencialidad, integridad y disponibilidad.",
      "Se conocen como «clave precompartida» o «clave secreta».",
      "Normalmente se utilizan con el tráfico VPN.",
      "Utilizan un par de clave pública y clave privada."
    ],
    "correct": [0, 4]
  },
  {
    "question": "¿Qué consideración es importante al implementar syslog en una red?",
    "options": [
      "Habilitar el nivel más alto de syslog disponible para garantizar el registro de todos los mensajes de eventos posibles.",
      "Utilizar SSH para acceder a la información de syslog.",
      "Sincronizar relojes en todos los dispositivos de red con un protocolo como Protocolo de hora de red.",
      "Registrar todos los mensajes en el búfer del sistema para que puedan mostrarse al acceder al enrutador."
    ],
    "correct": [2]
  },
  {
    "question": "¿Cuál meta-característica (meta-feature) del Modelo Diamante (Diamond Model) clasifica el tipo general de evento de intrusión?",
    "options": [
      "Metodología",
      "Dirección",
      "Fase",
      "Resultados"
    ],
    "correct": [0]
  },
  {
    "question": "¿Qué certificación patrocinada por Cisco está diseñada para proporcionar el primer paso en la adquisición de conocimientos y habilidades para trabajar con un equipo SOC?",
    "options": [
      "CCNA Data Center",
      "CCNA CyberOps Associate",
      "CCNA Security",
      "CCNA Cloud"
    ],
    "correct": [1]
  },
  {
    "question": "¿Cuál es una desventaja de DDNS?",
    "options": [
      "El DDNS se considera maligno y debe ser monitoreado por software de seguridad.",
      "Mediante los servicios gratuitos de DDNS, los atacantes pueden generar subdominios de forma rápida y sencilla y cambiar los registros DNS.",
      "DDNS no puede coexistir en un subdominio de red que también utiliza DNS.",
      "Con DDNS, un cambio en una asignación de direcciones IP existente puede tardar más de 24 horas y podría provocar una interrupción en la conectividad."
    ],
    "correct": [1]
  },
  {
    "question": "¿Cuáles son las dos formas en que los atacantes utilizan NTP? (Escoja dos opciones.)",
    "options": [
      "Utilizan sistemas NTP para dirigir ataques DDoS.",
      "Codifican los datos robados como una porción del subdominio donde el servidor de nombres (nameserver) esta bajo el control de un atacante.",
      "Colocan iFrames en una página web corporativa de uso frecuente.",
      "Colocan un archivo adjunto dentro de un mensaje de correo electrónico.",
      "Atacan la infraestructura NTP con el fin de corromper la información utilizada para registrar el ataque."
    ],
    "correct": [0, 4]
  },
  {
    "question": "¿Cuál es el propósito principal de los ataques realizados por el actor de una amenaza a través del arma aplicada a un objetivo durante la fase de ataque de cadena de eliminación cibernética?",
    "options": [
      "Quebrar la vulnerabilidad y obtener el control del objetivo.",
      "Establecer una puerta trasera al sistema.",
      "Lanzar un ataque DoS.",
      "Enviar un mensaje a un CnC controlado por el actor de la amenaza."
    ],
    "correct": [0]
  },
  {
    "question": "¿Qué función central del NIST Cybersecurity Framework está relacionada con el desarrollo y la implementación de salvaguardias que garanticen la prestación de servicios de infraestructura críticos?",
    "options": [
      "respond",
      "protect",
      "recover",
      "identify",
      "detect"
    ],
    "correct": [1]
  },
  {
    "question": "El personal de seguridad de TI de una organización observa que el servidor web implementado en la DMZ suele ser el blanco de actores de amenazas. Se tomó la decisión de implementar un sistema de administración de parches para administrar el servidor. ¿Qué estrategia de gestión de riesgos se utiliza para responder al riesgo identificado?",
    "options": [
      "Reducción de riesgos",
      "Retención de riesgos",
      "Evitar riesgos",
      "Distribución compartida de riesgos"
    ],
    "correct": [0]
  },
  {
    "question": "¿Qué tres servicios son proporcionados a través de las firmas digitales? (Escoja tres opciones.)",
    "options": [
      "Proporcionar encriptación de datos",
      "Autenticación del origen",
      "Proporcionar confiabilidad de los datos firmados digitalmente",
      "Garantizar que los datos no han cambiado en tránsito",
      "Proporcionar no repudio usando funciones HMAC",
      "Autenticación del destino"
    ],
    "correct": [1, 3, 5]
  },
  {
    "question": "¿Qué comando de Linux se utiliza para administrar los procesos?",
    "options": [
      "grep",
      "ls",
      "kill",
      "chrootkit"
    ],
    "correct": [2]
  },
  {
    "question": "¿Qué beneficio se deriva de la conversión de los datos de archivos de registro en un esquema común?",
    "options": [
      "Permite la aplicación de inspección y normalización parciales",
      "Crea una serie de extracciones de campos basadas en regex.",
      "Crea un modelo de datos basado en campos de datos de una fuente.",
      "Permite procesar y analizar conjuntos de datos con facilidad."
    ],
    "correct": [3]
  },
  {
    "question": "¿Cuáles son las etapas que completa un dispositivo inalámbrico antes de que pueda comunicarse a través de una red LAN inalámbrica (Wireless LAN WLAN)?",
    "options": [
      "Descubrir un punto de acceso (Access Point AP) inalámbrico, autorizarse con el AP, asociarse con el AP",
      "Descubrir un punto de acceso (Access Point AP) inalámbrico, autenticarse con el AP, asociarse con el AP",
      "Descubrir un punto de acceso (Access Point AP) inalámbrico, asociarse con el AP, autorizarse con el AP",
      "Descubrir un punto de acceso (Access Point AP) inalámbrico, asociarse con el AP, autenticarse con el AP"
    ],
    "correct": [1]
  },
  {
    "question": "Un administrador de red decide revisar las alertas del servidor debido a que recibió reportes sobre la lentitud de la red. El administrador confirma que una alerta fue un incidente de seguridad real. ¿Cuál es la clasificación de la alerta de seguridad en este tipo de escenario?",
    "options": [
      "Positivo verdadero",
      "Negativo verdadero",
      "Falso positivo",
      "Falso negativo"
    ],
    "correct": [0]
  },
  {
    "question": "¿Qué enfoque puede ayudar a bloquear métodos potenciales de aplicación de malware, como se describe en el modelo de cadena de eliminación cibernética, en un servidor web con contacto con Internet?",
    "options": [
      "Desarrollar detecciones para el comportamiento de malware conocido.",
      "Reunir archivos y metadatos de malware para análisis futuros.",
      "Analizar la ruta de almacenamiento de la infraestructura utilizada para los archivos.",
      "Auditar el servidor web para determinar, desde un punto de vista forense, el origen del ataque."
    ],
    "correct": [2]
  },
  {
    "question": "Cuáles dos opciones corresponden a gestores de ventanas para Linux? (Escoja dos opciones.)",
    "options": [
      "File Explorer",
      "Gnome",
      "Kali",
      "KDE",
      "PenTesting"
    ],
    "correct": [1, 3]
  },
  {
    "question": "¿Qué tres direcciones IP se consideran direcciones privadas? (Elija tres.)",
    "options": [
      "198.168.6.18",
      "192.168.5.29",
      "172.68.83.35",
      "128.37.255.6",
      "172.17.254.4",
      "10.234.2.1"
    ],
    "correct": [1, 4, 5]
  },
  {
    "question": "Según la información descrita por Cyber ​​Kill Chain, ¿cuáles dos enfoques pueden ayudar a identificar las amenazas de reconocimiento? (Elija dos.)",
    "options": [
      "Analizar alertas de registro web y datos de búsqueda históricos.",
      "Auditoría de puntos finales para determinar de forma forense el origen del exploit.",
      "Cree guías para detectar el comportamiento del navegador.",
      "Realice un análisis completo de malware.",
      "Comprenda los servidores objetivo, las personas y los datos disponibles para atacar."
    ],
    "correct": [0, 2]
  },
  {
    "question": "¿Cuál es el propósito de Tor?",
    "options": [
      "Inspeccionar el tráfico entrante y buscar si se viola una regla o si coincide con la firma de una ataque conocido",
      "Establecer conexión segura con una red remota a través de un enlace inseguro, como una conexión a Internet",
      "Dar ciclos de procesador a tareas informáticas distribuidas en una red P2P de intercambio de procesadores",
      "Permitir que los usuarios naveguen por Internet de forma anónima"
    ],
    "correct": [3]
  },
  {
    "question": "Una empresa de TI recomienda el uso de aplicaciones PKI para intercambiar información de forma segura entre los empleados. ¿En qué dos casos podría una organización utilizar aplicaciones PKI para intercambiar información de forma segura entre usuarios? (Elija dos opciones). intercambiar información de forma segura entre usuarios? (Elija dos.)",
    "options": [
      "Transferencias FTP",
      "Servidor DNS local",
      "Servicio web HTTPS",
      "Permiso de acceso a archivos y directorios",
      "Autenticación 802.1x"
    ],
    "correct": [2, 4]
  },
  {
    "question": "¿Qué declaración define la diferencia entre los datos de sesión y los datos de transacción en los registros?",
    "options": [
      "Los datos de sesión analizan el tráfico de la red y predicen el comportamiento de la red, mientras que los datos de transacciones registran las sesiones de la red.",
      "Los datos de sesión se usan para hacer predicciones sobre el comportamiento de la red, mientras que los datos de transacciones se usan para detectar anomalías en la red.",
      "Los datos de sesión registran una conversación entre hosts, mientras que los datos de transacción se centran en el resultado de las sesiones de red.",
      "Los datos de sesión muestran el resultado de una sesión de red, mientras que los datos de transacción son una respuesta al tráfico de amenazas de red."
    ],
    "correct": [2]
  },
  {
    "question": "Un cliente está utilizando SLAAC para obtener una dirección IPv6 para la interfaz. Después de generar y aplicar una dirección a la interfaz, ¿qué debe hacer el cliente antes de que pueda comenzar a usar esta dirección IPv6?",
    "options": [
      "Debe enviar un mensaje de solicitud de enrutador ICMPv6 para determinar qué puerta de enlace predeterminada debe usar.",
      "Debe enviar un mensaje de solicitud de enrutador ICMPv6 para solicitar la dirección del servidor DNS.",
      "Debe enviar un mensaje de solicitud de vecino ICMPv6 para asegurarse de que la dirección no esté ya en uso en la red.",
      "Debe esperar un mensaje de anuncio de enrutador ICMPv6 que dé permiso para usar esta dirección."
    ],
    "correct": [2]
  },
  {
    "question": "¿Qué dos afirmaciones describen las características de los algoritmos simétricos? (Elija dos.)",
    "options": [
      "Se denominan clave precompartida o clave secreta.",
      "Utilizan un par de clave pública y clave privada.",
      "Se utilizan comúnmente con tráfico VPN.",
      "Proporcionan confidencialidad, integridad y disponibilidad."
    ],
    "correct": [0, 2]
  },
  {
    "question": "¿Qué enfoque puede ayudar a bloquear posibles métodos de entrega de malware, como se describe en el modelo Cyber ​​Kill Chain, en un servidor web con acceso a Internet?",
    "options": [
      "Cree detecciones para el comportamiento de malware conocido.",
      "Recopilar archivos de malware y metadatos para análisis futuros.",
      "Auditoría del servidor web para determinar de manera forense el origen del exploit.",
      "Analice la ruta de almacenamiento de la infraestructura utilizada para los archivos."
    ],
    "correct": [3]
  }

];

/* const questions = [
  
]; */

// Inicializar el cuestionario
const quizContainer = document.getElementById('quiz-container');
const submitButton = document.getElementById('submit');
const scoreElement = document.getElementById('score');
let userAnswers = questions.map(() => new Set()); // Respuestas del usuario como conjuntos para manejar selecciones múltiples

// Estado inicial: deshabilitar el botón de resultados
submitButton.disabled = true;

// Crear mensaje indicativo dinámico
const messageElement = document.createElement('p');
messageElement.id = 'message';
messageElement.style.textAlign = 'center';
messageElement.style.fontWeight = 'bold';
messageElement.style.color = '#ff0000';
messageElement.textContent = `Responde todas las preguntas para ver los resultados.`;
quizContainer.appendChild(messageElement);

// console.log(questions.length)

// Renderizar las preguntas
questions.forEach((q, index) => {
    const questionDiv = document.createElement('div');
    questionDiv.classList.add('question');

    // Crea y añade el texto de la pregunta
    const questionText = document.createElement('p');
    questionText.textContent = q.question;
    questionDiv.appendChild(questionText);

    // Si existe una URL de imagen, la crea y la añade
    if (q.imageURL) {
        const questionImage = document.createElement('img');
        questionImage.src = q.imageURL;
        questionImage.alt = "Ilustración de la pregunta";
        questionImage.classList.add('question-image'); 
        questionDiv.appendChild(questionImage);
    }

    // A partir de aquí, el código es el mismo para las opciones
    q.options.forEach((option, i) => {
        const optionButton = document.createElement('div');
        optionButton.classList.add('option');
        optionButton.textContent = option;

        // Evento para manejar la selección de opciones
        optionButton.addEventListener('click', () => {
            // Si es una pregunta con múltiples respuestas correctas
            if (q.correct.length > 1) {
                if (userAnswers[index].has(i)) {
                    userAnswers[index].delete(i); // Desmarcar si ya está seleccionada
                    optionButton.classList.remove('selected');
                } else {
                    userAnswers[index].add(i); // Marcar como seleccionada
                    optionButton.classList.add('selected');
                }
            } else {
                // Pregunta con una única respuesta correcta
                const allOptions = questionDiv.querySelectorAll('.option');
                allOptions.forEach(opt => {
                    opt.classList.remove('disabled');
                    opt.style.pointerEvents = 'auto';
                });
                userAnswers[index] = new Set([i]);
            }

            // Deshabilitar pregunta si todas las opciones están seleccionadas (para preguntas múltiples)
            if (userAnswers[index].size === q.correct.length || q.correct.length === 1) {
                const allOptions = questionDiv.querySelectorAll('.option');
                allOptions.forEach(opt => {
                    opt.classList.add('disabled');
                    opt.style.pointerEvents = 'none';
                });

                // Resaltar respuestas correctas e incorrectas
                allOptions.forEach((opt, j) => {
                    if (q.correct.includes(j)) {
                        opt.classList.remove('selected');
                        opt.classList.add('correct'); // Verde
                    } else if (userAnswers[index].has(j)) {
                        opt.classList.remove('selected');
                        opt.classList.add('incorrect'); // Rojo
                    }
                });

                // Mostrar retroalimentación
                const feedback = document.createElement('p');
                feedback.classList.add('feedback');

                const isCorrect = [...userAnswers[index]].every(
                    selected => q.correct.includes(selected)
                ) && userAnswers[index].size === q.correct.length;

                if (isCorrect) {
                    feedback.textContent = "¡Correcto!";
                    feedback.classList.add('feedback-correct');
                } else {
                    feedback.textContent = "¡Incorrecto!";
                    feedback.classList.add('feedback-incorrect');
                }
                questionDiv.appendChild(feedback);

                // Actualizar estado del botón "Ver resultados"
                checkIfAllAnswered();
            }
        });

        questionDiv.appendChild(optionButton);
    });

    quizContainer.appendChild(questionDiv);
});

// Validar si todas las preguntas fueron respondidas
function checkIfAllAnswered() {
    const allAnswered = userAnswers.every(
        (answer, index) => answer.size > 0 || (questions[index].correct.length === 1 && answer.size === 1)
    );

    if (allAnswered) {
        submitButton.disabled = false;
        messageElement.textContent = "¡Ya puedes ver los resultados!";
        messageElement.style.color = "#28a745"; // Verde
    } else {
        submitButton.disabled = true;
        const unanswered = userAnswers.filter(answer => answer.size === 0).length;
        messageElement.textContent = `Faltan ${unanswered} pregunta(s) por responder.`;
        messageElement.style.color = "#ff0000"; // Rojo
    }
}

// Mostrar los resultados al hacer clic en el botón
submitButton.addEventListener('click', () => {
    let score = 0;

    // Calcular el puntaje solo con respuestas correctas
    userAnswers.forEach((answer, index) => {
        const isCorrect = [...answer].every(selected => questions[index].correct.includes(selected)) &&
                          answer.size === questions[index].correct.length;

        if (isCorrect) {
            score++;
        }
    });

    scoreElement.textContent = `Tu puntaje es: ${score} de ${questions.length}`;
});

