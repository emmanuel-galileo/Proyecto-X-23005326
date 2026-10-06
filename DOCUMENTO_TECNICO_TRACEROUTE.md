# Especificación Técnica del Protocolo y Mecanismo de Diagnóstico Traceroute (`my_traceroute`)

**Asignatura**: Ciencias de la Computación VIII  
**Proyecto**: #02 — Traceroute mediante RAW Sockets  
**Estándar de Implementación**: C99 / POSIX  
**Referencias Normativas**: RFC 791, RFC 792, RFC 768, RFC 1071, RFC 1122  

---

## 1. Introducción y Marco Normativo

El presente documento constituye la especificación formal del protocolo de sondeo y diagnóstico implementado en la herramienta `my_traceroute`. El sistema reproduce el mecanismo clásico de rastreo de rutas en redes de paquetes IPv4 a bajo nivel, construyendo datagramas manualmente y gestionando la comunicación directamente mediante sockets crudos (*RAW sockets*), sin intermediación de librerías de generación de tráfico de alto nivel.

Siguiendo la metodología de especificación técnica formal (tomando como referencia el rigor estructural de documentos como RFC 9293 para protocolos de transporte), este documento describe la estructura binaria de los paquetes, los algoritmos de control, las políticas de temporización y descarte, y las decisiones de diseño adoptadas.

### 1.1 Referencias Normativas Citables

| Estándar | Título / Ámbito | Rol en el Proyecto |
| :--- | :--- | :--- |
| **RFC 791** | *Internet Protocol (IPv4)* | Formato de la cabecera IPv4, decremento de TTL y cálculo de longitud total. |
| **RFC 768** | *User Datagram Protocol (UDP)* | Formato de la cabecera UDP, cálculo de longitud y regla del checksum nulo (`0xFFFF`). |
| **RFC 792** | *Internet Control Message Protocol (ICMP)* | Mensajes de control de retorno: *Time Exceeded* (Tipo 11) y *Destination Unreachable* (Tipo 3). |
| **RFC 1071** | *Computing the Internet Checksum* | Algoritmo de suma en complemento a uno de 16 bits para IPv4, UDP e ICMP. |
| **RFC 1122** | *Requirements for Internet Hosts* | Comportamiento requerido ante datagramas UDP dirigidos a puertos cerrados (generación de ICMP Port Unreachable). |

---

## 2. Formato Binario de Paquetes y Estructuras de Datos

Para garantizar la compatibilidad exacta con los estándares de red y evitar que el compilador inserte bytes de alineación (*padding*), todas las estructuras binarias se compilan con empaquetamiento estricto a 1 byte (`#pragma pack(push, 1)`).

### 2.1 Datagrama de Sondeo IPv4 / UDP (Sonda Emitida)

Cada sonda (*probe*) transmitida tiene una longitud total fija de **52 bytes**, distribuida en:
- Cabecera IPv4: 20 bytes
- Cabecera UDP: 8 bytes
- Carga útil (Payload): 24 bytes

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length (52)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags (010)|   Fragment Off (0)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  TTL (1..64)  | Protocol (17) |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source IP Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination IP Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Length (32)         |            Checksum           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Payload Fijo (24 bytes: 0x42)                |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Campos de la Cabecera IPv4 (`ip_header_t` en `ip_header.h`)
- **Version / IHL** (`uint8_t`): `0x45` $\to$ Versión 4, IHL = 5 palabras de 32 bits (20 bytes).
- **TOS** (`uint8_t`): `0x00` (servicio estándar).
- **Total Length** (`uint16_t`): `52` bytes en orden de red (`htons(52)`).
- **Identification** (`uint16_t`): Asignado dinámicamente con el puerto destino para trazabilidad.
- **Flags / Fragment Offset** (`uint16_t`): `htons(0x4000)` $\to$ Flag *Don't Fragment* (DF) activo.
- **TTL** (`uint8_t`): Valor del salto evaluado ($1, 2, 3, \dots, N$).
- **Protocol** (`uint8_t`): `17` (`IPPROTO_UDP`).
- **Checksum** (`uint16_t`): Checksum RFC 1071 calculado sobre los 20 bytes del encabezado IP.
- **Source IP / Destination IP** (`uint32_t`): Direcciones en orden de red (*Network Byte Order*).

#### Campos de la Cabecera UDP (`udp_header_t` en `udp_header.h`)
- **Source Port** (`uint16_t`): Puerto base local efímero derivado del PID: `40000 + (getpid() & 0x3FFF)`.
- **Destination Port** (`uint16_t`): Puerto incremental único por sonda, comenzando en `33434`.
- **Length** (`uint16_t`): `htons(32)` ($8\text{ bytes UDP} + 24\text{ bytes payload}$).
- **Checksum** (`uint16_t`): Checksum RFC 768 calculado con Pseudo-Header IPv4.

---

### 2.2 Pseudo-Encabezado IPv4 para Checksum UDP

Conforme a RFC 768, el checksum UDP no se calcula de forma aislada, sino sobre un pseudo-encabezado de 12 bytes que enlaza información de la capa de red con la capa de transporte:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source IP Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination IP Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Zero     |    Protocol   |           UDP Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Implementado en `udp_header.c` (`udp_pseudo_header_t`):
$$\text{Checksum UDP} = \sim \Big( \sum \text{PseudoHeader} + \sum \text{UDP Header (checksum=0)} + \sum \text{Payload} \Big)$$
*Regla de RFC 768*: Si la suma en complemento a uno resulta `0x0000`, debe transmitirse como `0xFFFF` (ya que `0x0000` denota que el checksum no fue calculado).

---

### 2.3 Paquete de Respuesta ICMP (Estructura de Retorno y Desencapsulado)

Cuando un router intermedio o el host final responden, el socket receptor crudo (`SOCK_RAW`, `IPPROTO_ICMP`) entrega un búfer con la siguiente estructura anidada (RFC 792):

```text
+---------------------------------------------------------------+
|  Cabecera IPv4 Externa (20 bytes)                             |
|  - Origen: IP del router respondedor                          |
|  - Protocolo: 1 (IPPROTO_ICMP)                                |
+---------------------------------------------------------------+
|  Cabecera ICMP (8 bytes)                                      |
|  - Tipo 11, Código 0: Time-to-Live Exceeded in Transit        |
|  - Tipo 3, Código 3:  Destination Unreachable / Port Unreach  |
|  - Checksum ICMP (RFC 792)                                    |
+---------------------------------------------------------------+
|  Payload ICMP: Cabecera IPv4 Original Transmitida (20 bytes)  |
|  - Protocolo: 17 (UDP)                                        |
|  - Destino: IP de destino del sondeo                          |
+---------------------------------------------------------------+
|  Payload ICMP: Primeros 64 bits de la Cabecera UDP Original   |
|  - Source Port (coincide con nuestro puerto efímero local)    |
|  - Destination Port (coincide con el puerto de la sonda)      |
+---------------------------------------------------------------+
```

---

## 3. Algoritmos y Mecanismos de Control

### 3.1 Algoritmo de Cálculo de Checksum de Internet (RFC 1071)

Implementado de forma modular en `checksum.c`:
1. **Acumulación (`checksum_accumulate`)**: Procesa el búfer como palabras de 16 bits en orden de red acumulando en un entero de 32 bits. Si la longitud es impar, añade el byte sobrante desplazado 8 bits a la izquierda.
2. **Plegado de acarreos (`checksum_finish`)**: Suma repetidamente los bits de orden superior ($sum \gg 16$) a los 16 bits inferiores ($sum \ \& \ \text{0xFFFF}$) hasta eliminar cualquier desbordamiento.
3. **Complemento a uno**: Retorna `(uint16_t)~sum`.

```c
uint16_t calculate_checksum(const void *buffer, size_t size) {
    return checksum_finish(checksum_accumulate(0, buffer, size));
}
```

---

### 3.2 Algoritmo del Motor de Sondeo (Bucle de Saltos y Sondas)

El motor principal (`traceroute_engine.c`) opera mediante una máquina de estados determinista:

```
[Inicio]
   |
   v
[Inicializar Sockets RAW (TX: IPPROTO_RAW, RX: IPPROTO_ICMP)]
   |
   +---> For TTL = first_ttl to max_hops:
           |
           +---> Imprimir número de salto
           |
           +---> For Probe = 1 to probes_per_hop:
           |        |
           |        +--> Pausa entre probes (pause_ms)
           |        +--> Asignar puerto UDP incremental (dst_port = 33434 + k)
           |        +--> Ensamblar paquete (IPv4 + UDP + Payload) con TTL actual
           |        +--> Registrar timestamp T_start = clock_gettime(CLOCK_MONOTONIC)
           |        +--> Enviar paquete vía send_raw_packet()
           |        +--> Esperar respuesta mediante poll() hasta deadline (timeout_sec)
           |        +--> Si responde ICMP válido:
           |        |       RTT = T_recv - T_start
           |        |       Imprimir IP / DNS y RTT
           |        |       ¿Es ICMP Port Unreachable del Destino? -> meta_alcanzada = true
           |        +--> Si timeout:
           |                Imprimir "*"
           |
           +---> Salto completado (salto de línea)
           +---> Si meta_alcanzada == true -> TERMINAR BUCLE
   |
   v
[Cerrar Sockets y Finalizar]
```

---

### 3.3 Algoritmo de Correlación y Descarte de Paquetes ICMP

En un socket `SOCK_RAW` de tipo `IPPROTO_ICMP`, el kernel entrega **todos** los paquetes ICMP entrantes al host. Para evitar falsos positivos o procesar tráfico de otras aplicaciones, `parse_and_validate_icmp()` en `icmp_parser.c` ejecuta una validación estricta de cuatro etapas:

$$\text{Aceptar Sonda} \iff \begin{cases}
1. & \text{Validar checksum de IPv4 externa y checksum ICMP}. \\
2. & \text{ICMP Tipo} \in \{11, 3\}. \\
3. & \text{IPv4 interna: Protocolo} = 17 \land \text{Destino} = \text{IP destino configurada}. \\
4. & \text{UDP interna: Origen} = \text{local\_src\_port} \land \text{Destino} = \text{probe\_dst\_port}.
\end{cases}$$

Si cualquiera de las cuatro condiciones falla, el paquete se descarta de inmediato y el receptor continúa esperando en su ciclo de `poll()` hasta que se alcance el *deadline*.

---

### 3.4 Mecanismo de Temporización No Bloqueante y Timeout

Para garantizar mediciones de RTT precisas y tolerantes a fluctuaciones del sistema operativo:
- **Reloj Monotónico**: Se utiliza `CLOCK_MONOTONIC`, inmune a ajustes del reloj NTP del sistema.
- **Deadline Absoluto**: El tiempo límite se computa al momento de emitir la sonda:
  $$\text{Deadline} = T_{\text{start}} + \text{timeout\_sec}$$
- **Sondeo con `poll()`**: El descriptor receptor opera en modo no bloqueante (`O_NONBLOCK`). En cada iteración se computa el remanente en milisegundos hacia el deadline:
  $$\text{Remanente} = \lceil (\text{Deadline} - T_{\text{actual}}) \rceil$$
  Si `poll()` retorna 0, expira el timeout y se registra el asterisco (`*`).

---

## 4. Políticas de Protocolo y Decisiones de Diseño

### 4.1 ¿Por qué Sondas UDP en lugar de ICMP Echo Request?
* **Decisión**: Se implementó el mecanismo clásico de Van Jacobson (UDP a puertos altos $> 33434$) en lugar de sondas ICMP Echo.
* **Justificación**: 
  1. Los paquetes UDP a puertos cerrados fuerzan al host de destino a generar una respuesta determinista `ICMP Tipo 3, Código 3 (Port Unreachable)` según RFC 1122.
  2. Muchos enrutadores y firewalls descartan prioritariamente solicitudes ICMP Echo para mitigar escaneos, mientras que permiten el tránsito de tráfico UDP.
  3. Permite correlacionar cada sonda individualmente mediante su número de puerto destino único, evitando colisiones de ID de proceso.

### 4.2 Separación de Sockets Crudos (TX vs RX)
* **Emisor (`create_raw_sender_socket`)**: Utiliza `IPPROTO_RAW` con la opción `IP_HDRINCL` activada. Esto delega la responsabilidad completa del ensamblado del encabezado IPv4 a la aplicación, permitiendo manipular el campo TTL en cada transmisión.
* **Receptor (`create_icmp_receiver_socket`)**: Utiliza `IPPROTO_ICMP`. No es posible recibir respuestas ICMP a través del socket de transmisión UDP; se requiere un socket RAW dedicado para escuchar mensajes del protocolo de control 1.

### 4.3 Generación del Puerto Origen Local
* El puerto origen se deriva del PID del proceso (`local_src_port = 40000 + (getpid() & 0x3FFF)`). Esto garantiza que si se ejecutan dos instancias simultáneas de `my_traceroute`, ninguna consuma ni valide los probes de la otra.

### 4.4 Tratamiento de Multipath y Balanceo de Carga (ECMP)
* En redes con balanceo por múltiples rutas (*Equal-Cost Multi-Path*), diferentes sondas de un mismo salto pueden tomar caminos distintos. 
* **Política de salida**: `traceroute_output.c` almacena la última IP que respondió. Si un probe subsiguiente del mismo salto proviene de una IP distinta, imprime la nueva identidad `hostname (IP) Latencia`, reflejando visualmente la topología multipath.

---

## 5. Parámetros de Operación y Validación Experimental

### 5.1 Parámetros Configurables por CLI

Todos los parámetros mínimos exigidos en la especificación se encuentran implementados con validación estricta de rangos en `traceroute_cli.c`:

| Parámetro CLI | Variable Interna | Rango Válido | Valor por Defecto | Justificación Técnica |
| :--- | :--- | :---: | :---: | :--- |
| `-f, --first-ttl` | `first_ttl` | $1 \le N \le 255$ | **1** | Permite saltar enrutadores locales iniciales conocidos. |
| `-m, --max-hops` | `max_hops` | $1 \le N \le 255$ | **64** | Diámetro máximo estándar de Internet para evitar bucles infinitos. |
| `-q, --probes` | `probes_per_hop` | $1 \le N \le 255$ | **3** | Muestreo estadístico clásico para evaluar estabilidad de enlace. |
| `-w, --timeout` | `timeout_sec` | $1 \le S \le 2147$ | **3** seg | Margen suficiente para enlaces intercontinentales y routers lentos. |
| `-z, --pause` | `pause_ms` | $0 \le MS$ | **100** ms | Evita disparar políticas de *ICMP Rate Limiting* en enrutadores intermedios. |

---

### 5.2 Evidencia de Pruebas Experimentales Comparativas

Se ejecutaron pruebas comparativas lado a lado contra el comando nativo de Linux (`traceroute`), verificando los registros generados:

#### Caso 1: Destino Localhost (`127.0.0.1`)
```text
======================= my_traceroute =======================
traceroute to 127.0.0.1 (127.0.0.1), 64 hops max, 52 byte packets
 1  localhost (127.0.0.1)  0.021 ms  0.045 ms  0.040 ms

==================== traceroute nativo =====================
traceroute to 127.0.0.1 (127.0.0.1), 64 hops max, 52 byte packets
 1  localhost (127.0.0.1)  0.019 ms  0.021 ms  0.015 ms
```
* **Análisis**: Ambas herramientas finalizan en el salto 1 tras recibir el `Port Unreachable` del host local, midiendo latencias sub-milisegundo concordantes.

#### Caso 2: Destino Remoto (`galileo.edu` $\to$ `104.20.20.230`)
Prueba ejecutada con: `-f 1 -m 8 -q 3 -w 1 -z 100`
```text
======================= my_traceroute =======================
traceroute to 104.20.20.230 (104.20.20.230), 8 hops max, 52 byte packets
 1  DESKTOP-AT70I2G.mshome.net (172.17.32.1)  0.138 ms  0.401 ms  0.229 ms
 2   *  *  *
 3   *  *  *
 4   *  *  *
 5   *  *  *
 6   *  *  *
 7   *  *  *
 8   *  *  *

==================== traceroute nativo =====================
traceroute to 104.20.20.230 (104.20.20.230), 8 hops max, 52 byte packets
 1  DESKTOP-AT70I2G.mshome.net (172.17.32.1)  0.377 ms  0.234 ms  0.199 ms
 2  * * *
 3  * * *
 4  * * *
 5  * * *
 6  * * *
 7  * * *
 8  * * *
```

---

### 5.3 Análisis Técnico de Discrepancias y Comportamiento de Red

1. **Diferencia en el Tamaño Total del Paquete**:
   - `my_traceroute` utiliza **52 bytes** ($20\text{ IP} + 8\text{ UDP} + 24\text{ payload}$), respetando la especificación original de Traceroute clásica mostrada en la guía del proyecto.
   - El `traceroute` moderno de Linux utiliza **60 bytes** por defecto ($20\text{ IP} + 8\text{ UDP} + 32\text{ payload}$). Al forzar la prueba nativa a 52 bytes (`traceroute ... 52`), ambas herramientas presentan un comportamiento binario idéntico.
2. **Causa de Timeouts en Entornos Virtualizados (WSL2 / NAT)**:
   - En el salto 1, el gateway virtual Hyper-V (`172.17.32.1`) responde inmediatamente a ambas herramientas.
   - A partir del salto 2, el switch virtual de Hyper-V o el cortafuegos NAT de Windows descarta los paquetes de retorno `ICMP Time Exceeded` que provienen de la interfaz física externa dirigidos hacia la subred virtual interna. Ambas herramientas registran timeouts idénticos (`*  *  *`), lo que confirma que el comportamiento responde estrictamente a la topología de red y no a fallas de implementación.
3. **ICMP Rate Limiting**:
   - Determinados enrutadores troncales limitan deliberadamente la tasa de generación de mensajes ICMP por segundo para proteger su CPU. El parámetro `-z 100` (100 ms de pausa entre probes) mitiga este descarte artificial.

---

## 6. Guía Rápida para la Defensa Presencial

Esta sección resume las respuestas técnicas ante las preguntas de evaluación obligatorias:

1. **¿Qué sucede exactamente a nivel de paquetes desde que se emite la sonda hasta que se recibe la respuesta?**
   * El cliente ensambla un paquete IPv4/UDP con TTL=$k$ y puerto destino $P$.
   * Cada router intermedio decrementa el campo TTL en 1.
   * Cuando un router recibe un paquete con TTL=1 y lo reduce a 0, descarta el paquete y genera un mensaje `ICMP Tipo 11, Código 0 (Time Exceeded)`.
   * El router empaqueta en el cuerpo del ICMP la cabecera IP original y los primeros 64 bits de la cabecera UDP.
   * Nuestro socket receptor lee este ICMP, verifica que los puertos correspondan a la sonda emitida, calcula el RTT ($T_{\text{llegada}} - T_{\text{envío}}$) y muestra la IP del router.
2. **¿Por qué sabemos cuándo se llegó al destino final?**
   * El host destino no decrementa el TTL a 0 porque es el receptor final.
   * Al recibir un datagrama UDP en un puerto alto no asociado a ningún servicio activo (ej. 33434), el kernel del destino genera un mensaje `ICMP Tipo 3, Código 3 (Destination Unreachable / Port Unreachable)` según RFC 1122. Al detectar este código y verificar que la IP origen sea la del objetivo, el programa concluye exitosamente la traza.
3. **¿Cómo se calcula el Checksum UDP y por qué requiere un Pseudo-Header?**
   * Se requiere el Pseudo-Header IPv4 para garantizar la integridad no solo de los datos UDP sino también de las direcciones IP de origen y destino, evitando que datagramas mal direccionados sean entregados por error.
4. **¿Por qué se requieren permisos de administrador (`sudo` o `CAP_NET_RAW`)?**
   * Porque la apertura de sockets crudos (`SOCK_RAW`) con manipulación de cabeceras de red (`IP_HDRINCL`) e inspección directa de mensajes ICMP a nivel de kernel está restringida en sistemas Unix/Linux por motivos de seguridad.
